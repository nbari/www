//! Authorized single-file responses.
//!
//! The caller authorizes and prepares exactly one file handle ([`Opened`]) and
//! this module turns it into the HTTP response: validators, RFC 9110 §13.2.2
//! precondition precedence, single `Range` handling and body framing. No
//! pathname is ever reopened, and the only filesystem work left is reading the
//! bytes of a body that was too large to be read by the resolving job.
//!
//! Validator formats and header order match what the server has always sent.

use super::fs::Opened;
use axum::{
    body::{Body, Bytes},
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use http_body::Frame;
use std::{
    io::{self, Read as _, Seek as _},
    ops::RangeInclusive,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::SystemTime,
};

/// Seconds from the Unix epoch to year 10000, past which `httpdate` panics.
const YEAR_10000: u64 = 253_402_300_800;

/// Bytes requested from the blocking pool per streaming body chunk.
///
/// Each response in flight holds one chunk, so this is also the per-response
/// memory a client can pin by reading slowly. Measured with 100 stalled 4 MiB
/// responses: 64 `KiB` costs 53 MiB of RSS, 128 `KiB` costs 55 MiB and 256
/// `KiB` costs 100 MiB, while 256 `KiB` buys only 3% more throughput than 128
/// `KiB` on the 4 MiB workload. 128 `KiB` keeps that exposure flat against
/// the smallest chunk while still halving the pool handoffs per megabyte, and
/// stays at glibc's default mmap threshold.
const CHUNK: u64 = 128 * 1024;

/// Validators derived from the prepared handle's `fstat`.
struct Validators {
    last_modified: Option<httpdate::HttpDate>,
    etag: Option<HeaderValue>,
}

impl Validators {
    fn new(metadata: &std::fs::Metadata) -> Self {
        let none = Self {
            last_modified: None,
            etag: None,
        };
        let Ok(modified) = metadata.modified() else {
            return none;
        };
        // `httpdate` panics on pre-epoch instants and on years past 9999, so
        // an unrepresentable mtime drops both validators instead of taking
        // down the connection task.
        let Ok(age) = modified.duration_since(SystemTime::UNIX_EPOCH) else {
            return none;
        };
        if age.as_secs() >= YEAR_10000 {
            return none;
        }
        let etag = HeaderValue::from_str(&format!(
            "\"{:x}.{:08x}-{:x}\"",
            age.as_secs(),
            age.subsec_nanos(),
            metadata.len()
        ))
        .ok();
        Self {
            last_modified: Some(httpdate::HttpDate::from(modified)),
            etag,
        }
    }

    fn last_modified_value(&self) -> Option<HeaderValue> {
        self.last_modified
            .and_then(|date| HeaderValue::from_str(&date.to_string()).ok())
    }
}

/// Trim leading and trailing optional whitespace per RFC 9110 §5.6.3.
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map_or(0, |index| index + 1);
    bytes.get(start..end).unwrap_or_default()
}

/// Visit every entity-tag in a comma separated list, honouring commas inside
/// quoted strings (RFC 9110 §8.8.3). Short-circuits on the first match.
fn for_each_etag(header: &[u8], mut predicate: impl FnMut(&[u8]) -> bool) -> bool {
    let mut start = 0;
    let mut in_quotes = false;
    for (index, byte) in header.iter().enumerate() {
        match byte {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                let candidate = trim_ows(header.get(start..index).unwrap_or_default());
                if !candidate.is_empty() && predicate(candidate) {
                    return true;
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let candidate = trim_ows(header.get(start..).unwrap_or_default());
    !candidate.is_empty() && predicate(candidate)
}

/// Strong comparison per RFC 9110 §8.8.3.2.
fn strong_eq(etag: &HeaderValue, candidate: &[u8]) -> bool {
    !candidate.starts_with(b"W/") && etag.as_bytes() == candidate
}

/// Weak comparison per RFC 9110 §8.8.3.2.
fn weak_eq(etag: &HeaderValue, candidate: &[u8]) -> bool {
    let own = etag.as_bytes();
    let own = own.strip_prefix(b"W/").unwrap_or(own);
    let candidate = candidate.strip_prefix(b"W/").unwrap_or(candidate);
    own == candidate
}

fn http_date(value: &HeaderValue) -> Option<httpdate::HttpDate> {
    value.to_str().ok()?.parse().ok()
}

/// Outcome of evaluating the request preconditions.
enum Precondition {
    Proceed,
    Failed,
    NotModified,
}

/// RFC 9110 §13.2.2 precedence: `If-Match`, then `If-Unmodified-Since` only
/// when `If-Match` is absent, then `If-None-Match`, then `If-Modified-Since`
/// only when `If-None-Match` is absent.
fn preconditions(headers: &HeaderMap, validators: &Validators) -> Precondition {
    match headers.get(header::IF_MATCH).filter(|v| !v.is_empty()) {
        Some(if_match) => {
            let passes = validators.etag.as_ref().is_some_and(|etag| {
                if_match.as_bytes() == b"*"
                    || for_each_etag(if_match.as_bytes(), |tag| strong_eq(etag, tag))
            });
            if !passes {
                return Precondition::Failed;
            }
        }
        None => {
            if let Some(since) = headers.get(header::IF_UNMODIFIED_SINCE).and_then(http_date)
                && validators
                    .last_modified
                    .is_some_and(|modified| since < modified)
            {
                return Precondition::Failed;
            }
        }
    }

    match headers.get(header::IF_NONE_MATCH).filter(|v| !v.is_empty()) {
        Some(if_none_match) => {
            let passes = validators.etag.as_ref().is_none_or(|etag| {
                if_none_match.as_bytes() != b"*"
                    && !for_each_etag(if_none_match.as_bytes(), |tag| weak_eq(etag, tag))
            });
            if !passes {
                return Precondition::NotModified;
            }
        }
        None => {
            if let Some(since) = headers.get(header::IF_MODIFIED_SINCE).and_then(http_date)
                && validators
                    .last_modified
                    .is_some_and(|modified| since >= modified)
            {
                return Precondition::NotModified;
            }
        }
    }

    Precondition::Proceed
}

/// A parsed `Range` request against a known body size.
enum RangeOutcome {
    /// No usable range: serve the full body.
    Absent,
    Satisfiable(RangeInclusive<u64>),
    Unsatisfiable,
}

/// Parse a single byte range. Multi-range requests are ignored (the server has
/// never produced multipart responses), malformed or unsatisfiable ranges
/// become 416.
fn parse_range(raw: Option<&HeaderValue>, size: u64) -> RangeOutcome {
    let Some(raw) = raw else {
        return RangeOutcome::Absent;
    };
    let Ok(text) = raw.to_str() else {
        return RangeOutcome::Absent;
    };
    let Ok(parsed) = http_range_header::parse_range_header(text) else {
        return RangeOutcome::Unsatisfiable;
    };
    if parsed.ranges.len() > 1 {
        return RangeOutcome::Absent;
    }
    match parsed.validate(size) {
        Ok(mut ranges) => ranges.pop().map_or(RangeOutcome::Unsatisfiable, |range| {
            RangeOutcome::Satisfiable(range)
        }),
        Err(_) => RangeOutcome::Unsatisfiable,
    }
}

/// Decide whether an `If-Range` validator permits the range to be applied.
/// Weak, malformed, repeated or non-matching validators fall back to the full
/// body while the ordinary preconditions still apply.
fn if_range_matches(values: &[&HeaderValue], validators: &Validators) -> bool {
    let [single] = values else {
        return false;
    };
    let Ok(value) = single.to_str() else {
        return false;
    };
    let value = value.trim();
    if value.is_empty() || value.starts_with("W/") {
        return false;
    }
    if value.starts_with('"') {
        return value.ends_with('"')
            && validators
                .etag
                .as_ref()
                .is_some_and(|etag| etag.as_bytes() == value.as_bytes());
    }
    match (
        validators.last_modified,
        value.parse::<httpdate::HttpDate>(),
    ) {
        (Some(modified), Ok(parsed)) => modified == parsed,
        _ => false,
    }
}

/// The authorized bytes, either already in memory or still on the handle.
enum Source {
    Inline(Bytes),
    Handle(std::fs::File),
}

impl Source {
    /// Build the body for `length` bytes starting at `offset`.
    fn body(self, offset: u64, length: u64) -> Body {
        match self {
            Self::Inline(bytes) => {
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                let end = usize::try_from(offset.saturating_add(length))
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                Body::from(bytes.slice(start..end))
            }
            Self::Handle(file) => Body::new(FileBody {
                state: FileState::Idle(file),
                seek: (offset > 0).then_some(offset),
                remaining: length,
            }),
        }
    }
}

enum FileState {
    Idle(std::fs::File),
    Reading(tokio::task::JoinHandle<io::Result<(std::fs::File, Vec<u8>)>>),
    /// The file ended before `Content-Length` was satisfied. The next poll
    /// reports the error instead of a clean end of stream.
    Truncated,
    Done,
}

/// Streams a prepared handle in [`CHUNK`]-sized pieces, one blocking-pool
/// handoff per piece.
struct FileBody {
    state: FileState,
    seek: Option<u64>,
    remaining: u64,
}

impl Drop for FileBody {
    fn drop(&mut self) {
        // A disconnected client leaves a queued chunk read behind. Aborting
        // keeps a worker from allocating and reading CHUNK bytes for a
        // response nobody will receive.
        if let FileState::Reading(handle) = &self.state {
            handle.abort();
        }
    }
}

fn read_chunk(
    mut file: std::fs::File,
    seek: Option<u64>,
    want: u64,
) -> io::Result<(std::fs::File, Vec<u8>)> {
    if let Some(offset) = seek {
        file.seek(io::SeekFrom::Start(offset))?;
    }
    let mut buffer = Vec::with_capacity(usize::try_from(want).unwrap_or_default());
    // `read_to_end` fills the spare capacity without zeroing it first.
    io::Read::take(&file, want).read_to_end(&mut buffer)?;
    Ok((file, buffer))
}

impl http_body::Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        loop {
            match std::mem::replace(&mut this.state, FileState::Done) {
                FileState::Done => return Poll::Ready(None),
                FileState::Truncated => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "file shrank while it was being sent",
                    ))));
                }
                FileState::Idle(file) => {
                    if this.remaining == 0 {
                        return Poll::Ready(None);
                    }
                    let want = this.remaining.min(CHUNK);
                    let seek = this.seek.take();
                    this.state = FileState::Reading(tokio::task::spawn_blocking(move || {
                        read_chunk(file, seek, want)
                    }));
                }
                FileState::Reading(mut handle) => {
                    let polled = Pin::new(&mut handle).poll(cx);
                    let joined = match polled {
                        Poll::Pending => {
                            this.state = FileState::Reading(handle);
                            return Poll::Pending;
                        }
                        Poll::Ready(joined) => joined,
                    };
                    let (file, buffer) = match joined {
                        Ok(Ok(read)) => read,
                        Ok(Err(error)) => return Poll::Ready(Some(Err(error))),
                        Err(error) => return Poll::Ready(Some(Err(io::Error::other(error)))),
                    };
                    let want = this.remaining.min(CHUNK);
                    let read = u64::try_from(buffer.len()).unwrap_or_default();
                    this.remaining = this.remaining.saturating_sub(read);
                    // A short read means `read_to_end` already hit EOF, so the
                    // advertised Content-Length can no longer be met. Signalling
                    // an error (rather than a clean end of stream) is what makes
                    // HTTP/2 reset the stream instead of delivering a silently
                    // truncated 200.
                    if read < want {
                        if this.remaining == 0 {
                            return Poll::Ready(None);
                        }
                        this.state = FileState::Truncated;
                    } else {
                        this.state = FileState::Idle(file);
                    }
                    if buffer.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(buffer)))));
                }
            }
        }
    }

    // Deliberately no `is_end_stream`/`size_hint` override: the framing must
    // stay driven by the explicit `Content-Length`, which also keeps the
    // header order identical for zero-length bodies.
}

/// Insert the headers every successful response carries, in the order the
/// server has always emitted them.
fn common_headers(headers: &mut HeaderMap, mime: Option<&HeaderValue>, validators: &Validators) {
    if let Some(mime) = mime {
        headers.insert(header::CONTENT_TYPE, mime.clone());
    }
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(last_modified) = validators.last_modified_value() {
        headers.insert(header::LAST_MODIFIED, last_modified);
    }
    if let Some(etag) = validators.etag.clone() {
        headers.insert(header::ETAG, etag);
    }
}

/// Serve the prepared handle.
///
/// `inline` carries the complete body when the resolving blocking job already
/// read it. `original` is the request's logical path and decides the MIME type.
pub(super) fn serve(
    opened: Opened,
    inline: Option<Vec<u8>>,
    original: &Path,
    request: &Request,
) -> Response {
    let Opened { file, metadata } = opened;
    let size = metadata.len();
    let validators = Validators::new(&metadata);
    let headers = request.headers();
    let is_head = request.method() == Method::HEAD;

    match preconditions(headers, &validators) {
        Precondition::Failed => return StatusCode::PRECONDITION_FAILED.into_response(),
        Precondition::NotModified => {
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            let target = response.headers_mut();
            if let Some(etag) = validators.etag.clone() {
                target.insert(header::ETAG, etag);
            }
            if let Some(last_modified) = validators.last_modified_value() {
                target.insert(header::LAST_MODIFIED, last_modified);
            }
            return response;
        }
        Precondition::Proceed => {}
    }

    // HEAD never honours `Range`, so `If-Range` cannot apply either.
    //
    // RFC 9110 §13.1.5: a failing `If-Range` makes the server ignore `Range`
    // entirely, so it is evaluated BEFORE parsing. Deciding it afterwards
    // would let an unsatisfiable or malformed range still produce 416.
    let range = if is_head {
        RangeOutcome::Absent
    } else {
        let raw = headers.get(header::RANGE);
        let if_range: Vec<&HeaderValue> = headers.get_all(header::IF_RANGE).iter().collect();
        if raw.is_some() && !if_range.is_empty() && !if_range_matches(&if_range, &validators) {
            RangeOutcome::Absent
        } else {
            parse_range(raw, size)
        }
    };

    let mime = mime_guess::from_path(original).first_or_octet_stream();
    let mime = HeaderValue::from_str(mime.as_ref())
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));

    if let RangeOutcome::Unsatisfiable = range {
        // Insert `Content-Type` and drop it again so the remaining fields keep
        // the exact order the server has always produced for 416.
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
        let target = response.headers_mut();
        common_headers(target, Some(&mime), &validators);
        if let Ok(value) = HeaderValue::from_str(&format!("bytes */{size}")) {
            target.insert(header::CONTENT_RANGE, value);
        }
        target.remove(header::CONTENT_TYPE);
        return response;
    }

    let source = match inline {
        Some(body) => Source::Inline(Bytes::from(body)),
        None => Source::Handle(file),
    };

    let (status, offset, length, content_range) = match range {
        RangeOutcome::Satisfiable(range) => {
            let (start, end) = (*range.start(), *range.end());
            let length = if size == 0 { 0 } else { end - start + 1 };
            (
                StatusCode::PARTIAL_CONTENT,
                start,
                length,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{size}")).ok(),
            )
        }
        _ => (StatusCode::OK, 0, size, None),
    };

    let body = if is_head {
        Body::empty()
    } else {
        source.body(offset, length)
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let target = response.headers_mut();
    common_headers(target, Some(&mime), &validators);
    if let Some(content_range) = content_range {
        target.insert(header::CONTENT_RANGE, content_range);
    }
    target.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response
}
