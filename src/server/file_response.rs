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
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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

/// Whether any entity-tag across every field line of `name` satisfies
/// `predicate`. RFC 9110 §5.3: repeated field lines are equivalent to one
/// comma-joined list, so all of them are consulted, not just the first.
fn any_etag(
    headers: &HeaderMap,
    name: header::HeaderName,
    mut predicate: impl FnMut(&[u8]) -> bool,
) -> bool {
    headers
        .get_all(name)
        .iter()
        .any(|value| for_each_etag(value.as_bytes(), &mut predicate))
}

/// Whether `name` is present as a wildcard across any of its field lines.
fn has_wildcard(headers: &HeaderMap, name: header::HeaderName) -> bool {
    headers
        .get_all(name)
        .iter()
        .any(|value| trim_ows(value.as_bytes()) == b"*")
}

/// RFC 9110 §13.2.2 precedence: `If-Match`, then `If-Unmodified-Since` only
/// when `If-Match` is absent, then `If-None-Match`, then `If-Modified-Since`
/// only when `If-None-Match` is absent.
///
/// A present-but-empty field is still present: it carries an empty list that
/// nothing can match, and it still suppresses the date-based condition below
/// it.
fn preconditions(headers: &HeaderMap, validators: &Validators) -> Precondition {
    if headers.contains_key(header::IF_MATCH) {
        let passes = validators.etag.as_ref().is_some_and(|etag| {
            has_wildcard(headers, header::IF_MATCH)
                || any_etag(headers, header::IF_MATCH, |tag| strong_eq(etag, tag))
        });
        if !passes {
            return Precondition::Failed;
        }
    } else if let Some(since) = headers.get(header::IF_UNMODIFIED_SINCE).and_then(http_date)
        && validators
            .last_modified
            .is_some_and(|modified| since < modified)
    {
        return Precondition::Failed;
    }

    if headers.contains_key(header::IF_NONE_MATCH) {
        let passes = validators.etag.as_ref().is_none_or(|etag| {
            !has_wildcard(headers, header::IF_NONE_MATCH)
                && !any_etag(headers, header::IF_NONE_MATCH, |tag| weak_eq(etag, tag))
        });
        if !passes {
            return Precondition::NotModified;
        }
    } else if let Some(since) = headers.get(header::IF_MODIFIED_SINCE).and_then(http_date)
        && validators
            .last_modified
            .is_some_and(|modified| since >= modified)
    {
        return Precondition::NotModified;
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

/// Parse a single byte range.
///
/// RFC 9110 §14.2: a range unit the server does not understand must be
/// ignored, not rejected. §14.1.2: a suffix length larger than the
/// representation selects the whole representation. A zero-length
/// representation can satisfy no byte range at all. Multi-range requests are
/// ignored because the server has never produced multipart responses.
fn parse_range(raw: Option<&HeaderValue>, size: u64) -> RangeOutcome {
    let Some(raw) = raw else {
        return RangeOutcome::Absent;
    };
    let Ok(text) = raw.to_str() else {
        return RangeOutcome::Absent;
    };
    // The range unit is a case-insensitive token; anything but `bytes` is
    // ignored, and the parser only accepts the canonical spelling.
    let Some((unit, spec)) = text.split_once('=') else {
        return RangeOutcome::Unsatisfiable;
    };
    let spec = spec.trim();
    if !unit.eq_ignore_ascii_case("bytes") {
        return RangeOutcome::Absent;
    }
    // The canonical spelling is parsed in place; only a differently-cased
    // unit needs a normalized copy.
    let normalized;
    let canonical = if unit == "bytes" {
        text
    } else {
        normalized = format!("bytes={spec}");
        &normalized
    };
    let Ok(parsed) = http_range_header::parse_range_header(canonical) else {
        return RangeOutcome::Unsatisfiable;
    };
    if parsed.ranges.len() > 1 {
        return RangeOutcome::Absent;
    }
    if size == 0 {
        return RangeOutcome::Unsatisfiable;
    }
    if let Ok(mut ranges) = parsed.validate(size)
        && let Some(range) = ranges.pop()
    {
        return RangeOutcome::Satisfiable(range);
    }
    // A suffix length beyond the representation is not an error: it selects
    // everything. This is the only recoverable validation rejection.
    if let Some(length) = spec.trim().strip_prefix('-')
        && let Ok(length) = length.trim().parse::<u64>()
        && length >= size
    {
        return RangeOutcome::Satisfiable(0..=size - 1);
    }
    RangeOutcome::Unsatisfiable
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

/// Smallest streaming chunk, used once the memory budget is exhausted. Small
/// enough that many more responses fit, large enough to stay far from the
/// per-chunk handoff cost that made 64 `KiB` the slowest setting measured.
const MIN_CHUNK: u64 = 16 * 1024;

/// Total bytes streaming bodies may hold across all connections.
///
/// A response in flight pins its chunk until the client reads it, so without
/// a ceiling the memory a slow reader can hold grows with the number of
/// connections. Beyond this, further bodies stream in [`MIN_CHUNK`] pieces
/// instead: slower, but bounded. Nothing ever waits or fails on the budget.
pub(super) const STREAM_BUDGET: u64 = 64 * 1024 * 1024;

/// Tracks the bytes currently reserved by streaming bodies.
#[derive(Debug)]
pub(super) struct BodyBudget {
    used: AtomicU64,
    limit: u64,
}

impl BodyBudget {
    pub(super) const fn new(limit: u64) -> Self {
        Self {
            used: AtomicU64::new(0),
            limit,
        }
    }

    /// Reserve a chunk for one body: the preferred size when it fits, else
    /// the minimum, else the minimum unreserved so a request never fails for
    /// want of budget.
    fn acquire(&self, want: u64) -> (u64, u64) {
        for size in [want, MIN_CHUNK] {
            let mut used = self.used.load(Ordering::Acquire);
            loop {
                let next = used.saturating_add(size);
                if next > self.limit {
                    break;
                }
                match self.used.compare_exchange_weak(
                    used,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return (size, size),
                    Err(current) => used = current,
                }
            }
        }
        (MIN_CHUNK, 0)
    }

    fn release(&self, reserved: u64) {
        if reserved > 0 {
            self.used.fetch_sub(reserved, Ordering::AcqRel);
        }
    }

    #[cfg(test)]
    fn in_use(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

/// The authorized bytes, either already in memory or still on the handle.
enum Source {
    Inline(Bytes),
    Handle(std::fs::File),
}

impl Source {
    /// Build the body for `length` bytes starting at `offset`.
    fn body(self, offset: u64, length: u64, budget: &Arc<BodyBudget>) -> Body {
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
            Self::Handle(file) => {
                let (chunk, reserved) = budget.acquire(CHUNK.min(length.max(1)));
                Body::new(FileBody {
                    state: FileState::Idle(file),
                    seek: (offset > 0).then_some(offset),
                    remaining: length,
                    chunk,
                    reserved,
                    budget: Arc::clone(budget),
                })
            }
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

/// Streams a prepared handle in `chunk`-sized pieces, one blocking-pool
/// handoff per piece.
struct FileBody {
    state: FileState,
    seek: Option<u64>,
    remaining: u64,
    chunk: u64,
    reserved: u64,
    budget: Arc<BodyBudget>,
}

impl Drop for FileBody {
    fn drop(&mut self) {
        self.budget.release(self.reserved);
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
                    let want = this.remaining.min(this.chunk);
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
                    let want = this.remaining.min(this.chunk);
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
    budget: &Arc<BodyBudget>,
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
        source.body(offset, length, budget)
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

#[cfg(test)]
mod body_tests {
    use super::{BodyBudget, CHUNK, FileBody, FileState, MIN_CHUNK, STREAM_BUDGET, Source};
    use http_body::Body as _;
    use std::sync::Arc;
    use std::{future::poll_fn, io, pin::Pin};

    fn body_over(path: &std::path::Path, len: u64) -> Result<FileBody, io::Error> {
        Ok(FileBody {
            state: FileState::Idle(std::fs::File::open(path)?),
            seek: None,
            remaining: len,
            chunk: CHUNK,
            reserved: 0,
            budget: Arc::new(BodyBudget::new(STREAM_BUDGET)),
        })
    }

    async fn next_frame(body: &mut FileBody) -> Option<Result<axum::body::Bytes, io::Error>> {
        poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx))
            .await
            .map(|frame| frame.map(|frame| frame.into_data().unwrap_or_default()))
    }

    /// A file that shrinks after its `Content-Length` was published can no
    /// longer satisfy it. Ending the stream cleanly would make HTTP/2 deliver
    /// a silently truncated `200`, so the body must surface an error instead.
    #[tokio::test]
    async fn a_file_that_shrinks_mid_stream_fails_instead_of_ending_cleanly()
    -> Result<(), io::Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("shrinking.bin");
        let len = CHUNK * 3;
        std::fs::write(&path, vec![7_u8; usize::try_from(len).unwrap_or_default()])?;
        let mut body = body_over(&path, len)?;

        let first = next_frame(&mut body)
            .await
            .ok_or_else(|| io::Error::other("no first chunk"))??;
        assert_eq!(u64::try_from(first.len()).unwrap_or_default(), CHUNK);

        // Shrink the file below what the response already promised.
        std::fs::File::options()
            .write(true)
            .open(&path)?
            .set_len(1)?;

        loop {
            match next_frame(&mut body).await {
                Some(Err(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                    return Ok(());
                }
                Some(Ok(chunk)) => assert!(
                    !chunk.is_empty(),
                    "an empty frame must not be emitted as data"
                ),
                None => {
                    return Err(io::Error::other(
                        "stream ended cleanly despite an unsatisfied Content-Length",
                    ));
                }
            }
        }
    }

    /// The ordinary path still yields exactly the promised bytes and then
    /// ends, in `CHUNK`-sized pieces.
    #[tokio::test]
    async fn a_stable_file_yields_exactly_the_promised_bytes() -> Result<(), io::Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("stable.bin");
        let len = CHUNK + 17;
        std::fs::write(&path, vec![3_u8; usize::try_from(len).unwrap_or_default()])?;
        let mut body = body_over(&path, len)?;

        let mut total = 0_u64;
        let mut chunks = 0_u32;
        while let Some(chunk) = next_frame(&mut body).await {
            total += u64::try_from(chunk?.len()).unwrap_or_default();
            chunks += 1;
        }
        assert_eq!(total, len);
        assert_eq!(chunks, 2, "a body of CHUNK + 17 bytes takes two reads");
        Ok(())
    }

    /// The budget is what keeps slow readers from pinning memory in
    /// proportion to the number of connections. Bodies past the ceiling keep
    /// working, in smaller pieces, and every reservation comes back on drop.
    #[tokio::test]
    async fn the_stream_budget_caps_reservations_and_degrades_instead_of_failing()
    -> Result<(), io::Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("budget.bin");
        std::fs::write(
            &path,
            vec![1_u8; usize::try_from(CHUNK).unwrap_or_default()],
        )?;

        // A ceiling of two full chunks admits exactly two full-size bodies.
        let budget = Arc::new(BodyBudget::new(CHUNK * 2));
        let mut bodies = Vec::new();
        for _ in 0..2 {
            bodies.push(Source::Handle(std::fs::File::open(&path)?).body(0, CHUNK, &budget));
        }
        assert_eq!(budget.in_use(), CHUNK * 2);

        // The next bodies fall back to the minimum chunk rather than failing.
        for _ in 0..4 {
            bodies.push(Source::Handle(std::fs::File::open(&path)?).body(0, CHUNK, &budget));
        }
        assert!(
            budget.in_use() <= CHUNK * 2 + MIN_CHUNK * 4,
            "reservations exceeded the ceiling: {}",
            budget.in_use()
        );

        // Dropping every body returns the whole reservation.
        drop(bodies);
        assert_eq!(budget.in_use(), 0, "reservations leaked on drop");
        Ok(())
    }

    /// With the ceiling fully taken, a body still streams: it takes the
    /// minimum chunk without a reservation rather than failing the request.
    #[tokio::test]
    async fn an_exhausted_budget_still_serves_the_body() -> Result<(), io::Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("exhausted.bin");
        let len = MIN_CHUNK * 2;
        std::fs::write(&path, vec![9_u8; usize::try_from(len).unwrap_or_default()])?;

        // A ceiling of zero can never admit a reservation.
        let budget = Arc::new(BodyBudget::new(0));
        let mut body = FileBody {
            state: FileState::Idle(std::fs::File::open(&path)?),
            seek: None,
            remaining: len,
            chunk: MIN_CHUNK,
            reserved: 0,
            budget: Arc::clone(&budget),
        };
        assert_eq!(budget.acquire(CHUNK), (MIN_CHUNK, 0), "nothing is reserved");
        assert_eq!(budget.in_use(), 0);

        let mut total = 0_u64;
        while let Some(chunk) = next_frame(&mut body).await {
            let chunk = chunk?;
            assert!(u64::try_from(chunk.len()).unwrap_or_default() <= MIN_CHUNK);
            total += u64::try_from(chunk.len()).unwrap_or_default();
        }
        assert_eq!(total, len, "an exhausted budget must not truncate the body");
        Ok(())
    }

    /// A range body seeks once and then stops at the requested length rather
    /// than running to end of file.
    #[tokio::test]
    async fn a_range_body_starts_at_the_offset_and_stops_at_the_length() -> Result<(), io::Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("range.bin");
        std::fs::write(&path, b"0123456789")?;
        let mut body = FileBody {
            state: FileState::Idle(std::fs::File::open(&path)?),
            seek: Some(2),
            remaining: 4,
            chunk: CHUNK,
            reserved: 0,
            budget: Arc::new(BodyBudget::new(STREAM_BUDGET)),
        };
        let chunk = next_frame(&mut body)
            .await
            .ok_or_else(|| io::Error::other("no chunk"))??;
        assert_eq!(chunk.as_ref(), b"2345");
        assert!(next_frame(&mut body).await.is_none());
        Ok(())
    }
}
