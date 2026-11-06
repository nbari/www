use super::{Files, file_response, fs};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, percent_encode};
use std::{
    fmt::Write as _,
    io::{self, Read as _},
    os::unix::ffi::OsStrExt as _,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const URL_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Decode a request path and join it onto the document root in a single
/// allocation. Rejects NUL bytes, backslashes and any non-normal component so
/// a request can never escape the root.
fn request_path(root: &Path, url: &str) -> Option<PathBuf> {
    let decoded = percent_decode_str(url.trim_start_matches('/')).collect::<Vec<u8>>();
    if decoded.contains(&0) || decoded.contains(&b'\\') {
        return None;
    }
    let relative = Path::new(std::ffi::OsStr::from_bytes(&decoded));
    let mut path = PathBuf::with_capacity(root.as_os_str().len() + decoded.len() + 1);
    path.push(root);
    for part in relative.components() {
        match part {
            Component::Normal(name) => path.push(name),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

fn error(error: &io::Error) -> Response {
    // Policy/race denials from the protected resolver are indistinguishable
    // from a missing resource to the client (404); ordinary permission errors
    // remain 403.
    if fs::is_denied(error) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let status = match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => {
            tracing::error!(%error, "cannot serve file");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    status.into_response()
}

fn redirect(request: &Request, path: &str) -> Response {
    // A Location beginning with // changes the authority in a browser.
    let path = format!("/{}", path.trim_start_matches('/'));
    let target = match request.uri().query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    match HeaderValue::from_str(&target) {
        Ok(value) => (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, value)]).into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Largest body read into memory during resolution; larger files keep
/// streaming through the opened descriptor.
///
/// Inlining is what collapses a response to a single write syscall and no
/// further blocking-pool work, and it is worth about 27% on a 200 `KiB` file
/// and 60% on a 100 `KiB` one. It costs no extra memory against streaming:
/// with 100 stalled 200 `KiB` responses a 64 `KiB` cutoff retains 9.9 MiB and
/// a 256 `KiB` cutoff retains 9.9 MiB, because a streamed response pins a
/// chunk buffer of its own anyway.
const INLINE_MAX: u64 = 256 * 1024;

/// Outcome of the single blocking resolution job for one request.
#[allow(
    clippy::large_enum_variant,
    reason = "the large variant is the per-request hot path; boxing it would add an allocation"
)]
enum Resolved {
    /// An authorized regular file. `inline` holds the complete body when it
    /// was read inside the same blocking job.
    File {
        opened: fs::Opened,
        inline: Option<Vec<u8>>,
        logical: PathBuf,
    },
    /// A directory with no index: the caller enumerates it off the fast path.
    Directory { opened: fs::Opened, dir: PathBuf },
    /// The request is answered by a redirect built from the request URL.
    Redirect(Redirect),
}

#[derive(Clone, Copy)]
enum Redirect {
    /// A directory requested without a trailing slash.
    DirSlash,
    /// A regular file requested with a trailing slash.
    FileNoSlash,
    /// An explicit `/index.html` that is served from its parent directory.
    IndexParent,
}

/// Open one path through the protection (or unprotected) resolver.
fn open_one(files: &Files, path: &Path) -> io::Result<fs::Opened> {
    match &files.protected {
        Some(protected) => protected.open(path),
        None => fs::open(path),
    }
}

/// Read an authorized handle into memory, bounded by its `fstat` size so a
/// concurrently growing file can never produce an unbounded body.
///
/// A short read means the file shrank between `fstat` and the read. Returning
/// it would advertise a `Content-Length` the body cannot satisfy, which
/// desynchronizes a keep-alive connection, so the request fails instead.
fn read_inline(opened: &fs::Opened) -> io::Result<Vec<u8>> {
    let len = opened.metadata.len();
    let mut body = Vec::with_capacity(usize::try_from(len).unwrap_or_default());
    io::Read::take(&opened.file, len).read_to_end(&mut body)?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "file shrank while it was being read",
        ));
    }
    Ok(body)
}

/// Resolve one request against the filesystem: open the target, probe an
/// index, and read small bodies. Collapsing these steps into one call keeps a
/// request to a single filesystem round trip.
fn resolve(
    files: &Files,
    path: PathBuf,
    url_slash: bool,
    index_exact: bool,
    inline: bool,
) -> io::Result<Resolved> {
    let opened = open_one(files, &path)?;
    if opened.metadata.is_dir() {
        if !url_slash {
            return Ok(Resolved::Redirect(Redirect::DirSlash));
        }
        // Index path lookup is checked/opened independently; a policy denial
        // on the index is a 404 (not a missing index that falls back to 200).
        let index = path.join("index.html");
        match open_one(files, &index) {
            Ok(index_opened) if index_opened.metadata.is_file() => {
                let body = read_inline_if(&index_opened, inline)?;
                return Ok(Resolved::File {
                    opened: index_opened,
                    inline: body,
                    logical: index,
                });
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound && !fs::is_denied(&err) => {}
            Err(err) => return Err(err),
        }
        return Ok(Resolved::Directory { opened, dir: path });
    }
    if !opened.metadata.is_file() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    if index_exact {
        return Ok(Resolved::Redirect(Redirect::IndexParent));
    }
    if url_slash {
        return Ok(Resolved::Redirect(Redirect::FileNoSlash));
    }
    let body = read_inline_if(&opened, inline)?;
    Ok(Resolved::File {
        opened,
        inline: body,
        logical: path,
    })
}

/// Read the body inside the resolving job when the fast path can serve it.
///
/// Zero-length files are skipped: hyper rewrites the `Content-Length` of a
/// known-empty body, which would reorder response headers for no gain.
fn read_inline_if(opened: &fs::Opened, inline: bool) -> io::Result<Option<Vec<u8>>> {
    let len = opened.metadata.len();
    if inline && len > 0 && len <= INLINE_MAX {
        return read_inline(opened).map(Some);
    }
    Ok(None)
}

/// Whether the request carries a range or precondition header. Such a request
/// is answered from the opened descriptor instead of an eagerly read body, so
/// a conditional or ranged response never pays for bytes it will not send.
fn negotiated(headers: &axum::http::HeaderMap) -> bool {
    headers.contains_key(header::RANGE)
        || headers.contains_key(header::IF_RANGE)
        || headers.contains_key(header::IF_MATCH)
        || headers.contains_key(header::IF_NONE_MATCH)
        || headers.contains_key(header::IF_MODIFIED_SINCE)
        || headers.contains_key(header::IF_UNMODIFIED_SINCE)
}

/// How long one resolution may take before the filesystem is treated as slow.
///
/// A page-cache hit resolves in single-digit microseconds, so anything here
/// above that is "far from the fast path". 250 us was tried and measured
/// worse: ordinary scheduling outliers crossed it, and each false positive
/// costs a full cooldown on the blocking pool, which cut small-file
/// throughput from 244k to 170k req/s and raised context switches per
/// request from 0.16 to 1.1. A millisecond is clear of that noise while
/// still far below any real device or network round trip.
const SLOW_RESOLVE: Duration = Duration::from_millis(1);

/// How long to keep using the blocking pool after a slow resolution.
const SLOW_COOLDOWN: Duration = Duration::from_secs(1);

/// [`SLOW_COOLDOWN`] in nanoseconds, saturating.
fn cooldown_nanos() -> u64 {
    u64::try_from(SLOW_COOLDOWN.as_nanos()).unwrap_or(u64::MAX)
}

/// Chooses between resolving on the runtime thread and on the blocking pool.
///
/// A blocking-pool handoff costs two context switches and more CPU than the
/// filesystem work itself when the page cache is warm, which is the normal
/// case for a static file server, so resolutions run inline by default.
///
/// Two independent limits keep that from costing availability:
///
/// * At most [`Dispatch::limit`] resolutions run inline at once, leaving the
///   remaining runtime workers free to accept connections, drive timers,
///   answer ACME challenges and run shutdown. This bound holds even against a
///   filesystem that never returns, which a latency measurement cannot catch
///   because the slow resolution never finishes.
/// * Once a completed resolution exceeds [`Dispatch::slow`], every resolution
///   goes to the blocking pool for [`SLOW_COOLDOWN`], after which the fast
///   path resumes on its own.
#[derive(Debug)]
pub(super) struct Dispatch {
    /// Process-relative nanosecond deadline; resolutions run on the blocking
    /// pool until `base.elapsed()` passes it. Zero means "inline allowed".
    blocking_until: AtomicU64,
    /// Resolutions currently running on a runtime worker.
    in_flight: AtomicUsize,
    /// Hard ceiling on `in_flight`.
    limit: usize,
    /// Completed-resolution latency above which the pool takes over.
    slow: Duration,
    base: Instant,
}

/// Releases an inline slot, including while a panic unwinds.
struct InlineSlot<'a>(&'a Dispatch);

impl Drop for InlineSlot<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Release);
    }
}

impl Dispatch {
    pub(super) fn new() -> Self {
        // Half the workers may block on the filesystem; the rest keep the
        // runtime responsive. A single-worker runtime never resolves inline.
        let workers = tokio::runtime::Handle::try_current()
            .map_or(1, |handle| handle.metrics().num_workers());
        Self::with_limits(workers / 2, SLOW_RESOLVE)
    }

    fn with_limits(limit: usize, slow: Duration) -> Self {
        Self {
            blocking_until: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            limit,
            slow,
            base: Instant::now(),
        }
    }

    /// Reserve a slot for an inline resolution, or `None` to use the pool.
    fn try_inline(&self) -> Option<InlineSlot<'_>> {
        let until = self.blocking_until.load(Ordering::Relaxed);
        if until != 0 {
            let now = self.now_nanos();
            if now < until {
                return None;
            }
            // The cooldown expired. Exactly one caller becomes the probe, by
            // claiming the deadline; everyone else keeps using the pool. A
            // burst of probes would be as damaging as never backing off.
            let next = now.saturating_add(cooldown_nanos());
            if self
                .blocking_until
                .compare_exchange(until, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                return None;
            }
        }
        if self.in_flight.fetch_add(1, Ordering::Acquire) >= self.limit {
            self.in_flight.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(InlineSlot(self))
    }

    /// Whether the fast path is currently open. Only the tests need to ask;
    /// `try_inline` folds this into its slot acquisition.
    #[cfg(test)]
    fn inline_allowed(&self) -> bool {
        let until = self.blocking_until.load(Ordering::Relaxed);
        until == 0 || self.now_nanos() >= until
    }

    fn now_nanos(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Record how long an inline resolution took. A slow one puts the server
    /// on the blocking pool; a fast one clears an outstanding cooldown, which
    /// is how the probe admitted by `try_inline` restores the fast path.
    /// `fetch_max` keeps two concurrent observations from moving the deadline
    /// backwards.
    fn observe(&self, elapsed: Duration) {
        if elapsed < self.slow {
            if self.blocking_until.load(Ordering::Relaxed) != 0 {
                self.blocking_until.store(0, Ordering::Relaxed);
            }
            return;
        }
        let until = self.now_nanos().saturating_add(cooldown_nanos());
        self.blocking_until.fetch_max(until, Ordering::Relaxed);
    }
}

pub(super) async fn serve(files: Arc<Files>, request: Request) -> Response {
    let (path, url_slash, index_exact) = {
        let url = request.uri().path();
        let Some(path) = request_path(&files.root, url) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        (path, url.ends_with('/'), url.ends_with("/index.html"))
    };
    let head = request.method() == Method::HEAD;
    let inline = !head && !negotiated(request.headers());
    let resolved = if let Some(slot) = files.dispatch.try_inline() {
        // Warm page cache: the handoff would cost more than the syscalls.
        //
        // The blocking pool turned a panic into a `JoinError` and then a 500.
        // Catching it here keeps that behaviour instead of unwinding through
        // the connection task, which would drop the connection with no
        // response at all.
        let started = Instant::now();
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resolve(&files, path, url_slash, index_exact, inline)
        }));
        files.dispatch.observe(started.elapsed());
        drop(slot);
        resolved.map_err(|_| io::Error::other("resolution panicked"))
    } else {
        let files = Arc::clone(&files);
        tokio::task::spawn_blocking(move || resolve(&files, path, url_slash, index_exact, inline))
            .await
            .map_err(io::Error::other)
    };
    match resolved {
        Err(err) => error(&io::Error::other(err)),
        Ok(Err(err)) => error(&err),
        Ok(Ok(Resolved::Redirect(kind))) => {
            let url = request.uri().path();
            match kind {
                Redirect::DirSlash => redirect(&request, &format!("{url}/")),
                Redirect::FileNoSlash => redirect(&request, url.trim_end_matches('/')),
                Redirect::IndexParent => {
                    let parent = url.strip_suffix("index.html").unwrap_or(url);
                    redirect(&request, parent)
                }
            }
        }
        // Enumerating and classifying a directory costs time proportional to
        // its entry count, which any client can inflate, so it always runs on
        // the blocking pool rather than on a runtime worker.
        Ok(Ok(Resolved::Directory { opened, dir })) => {
            let listed = {
                let files = Arc::clone(&files);
                tokio::task::spawn_blocking(move || -> io::Result<Vec<Row>> {
                    let entries = fs::list_entries(&opened.file)?;
                    Ok(classify_listing(&files, &dir, entries))
                })
                .await
            };
            match listed {
                Err(err) => error(&io::Error::other(err)),
                Ok(Err(err)) => error(&err),
                Ok(Ok(rows)) => listing(&rows, head),
            }
        }
        Ok(Ok(Resolved::File {
            opened,
            inline,
            logical,
        })) => file_response::serve(opened, inline, &logical, &request, &files.budget),
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A resolved listing row: raw name plus whether it renders as a directory.
type Row = (std::ffi::OsString, bool);

/// Enumerate and classify a directory listing entirely inside a blocking job.
///
/// Every entry is resolved through the protection so cache contents and
/// active-cache aliases are hidden (policy denial => hidden). A known
/// regular-file or directory label is preserved even when read-open yields an
/// ordinary `PermissionDenied` (listing needs no read permission); broken
fn classify_listing(files: &Files, dir: &Path, entries: Vec<fs::Entry>) -> Vec<Row> {
    let mut rows = Vec::new();
    for entry in entries {
        let is_dir = match &files.protected {
            None => {
                // Unprotected: the dirent file type is authoritative for known
                // regular files and directories (no per-entry open); symlink
                // and unknown types are classified with std::fs::metadata
                // (follows the link, no read permission required). Broken
                // symlinks and non-file/non-dir types are hidden.
                if entry.is_dir() {
                    Some(true)
                } else if entry.is_file() {
                    Some(false)
                } else {
                    let target = dir.join(&entry.name);
                    std::fs::metadata(&target)
                        .ok()
                        .filter(|m| m.is_file() || m.is_dir())
                        .map(|m| m.is_dir())
                }
            }
            Some(protected) => {
                // Protected: metadata-only classification through the same
                // descriptor walk + cache identity checks (no read permission).
                // Policy denial hides cache contents/aliases; a symlink leaf or
                // non-file/non-dir target is hidden.
                let target = dir.join(&entry.name);
                match protected.classify(&target) {
                    Ok(is_dir) => Some(is_dir),
                    Err(err) if fs::is_denied(&err) => None,
                    Err(_) => None,
                }
            }
        };
        if let Some(is_dir) = is_dir {
            rows.push((entry.name, is_dir));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

fn listing(rows: &[Row], head: bool) -> Response {
    let mut html = String::from(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>Directory listing</title>\n<pre>\n",
    );
    for (name, directory) in rows {
        let suffix = if *directory { "/" } else { "" };
        let href = percent_encode(name.as_encoded_bytes(), URL_COMPONENT);
        let label = escape(&name.to_string_lossy());
        let _ = writeln!(html, "<a href=\"./{href}{suffix}\">{label}{suffix}</a>");
    }
    html.push_str("</pre>\n");
    let length = html.len();
    let mut response = if head {
        Body::empty()
    } else {
        Body::from(html)
    }
    .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(length) = HeaderValue::from_str(&length.to_string()) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length);
    }
    response
}

#[cfg(test)]
mod dispatch_tests {
    use super::{Dispatch, Files, SLOW_COOLDOWN, serve};
    use axum::{body::Body, extract::Request};
    use std::{sync::Arc, sync::atomic::Ordering, time::Duration};

    /// The cap is what keeps a filesystem that never returns from pinning
    /// every runtime worker: a latency threshold cannot help there, because
    /// the slow resolution never completes to be measured.
    #[test]
    fn inline_resolutions_are_capped_and_slots_are_returned() {
        let dispatch = Dispatch::with_limits(2, Duration::from_millis(1));
        let first = dispatch.try_inline();
        let second = dispatch.try_inline();
        assert!(first.is_some() && second.is_some());
        assert!(
            dispatch.try_inline().is_none(),
            "a third concurrent inline resolution must fall back to the pool"
        );
        assert_eq!(dispatch.in_flight.load(Ordering::Relaxed), 2);

        drop(first);
        assert!(
            dispatch.try_inline().is_some(),
            "dropping a slot must free it"
        );

        // A runtime with a single worker never blocks that worker inline.
        assert!(
            Dispatch::with_limits(0, Duration::from_millis(1))
                .try_inline()
                .is_none()
        );
    }

    /// A slow resolution must move the whole server onto the blocking pool,
    /// and the cooldown must expire on its own.
    #[test]
    fn a_slow_resolution_engages_and_then_releases_the_cooldown() {
        let dispatch = Dispatch::with_limits(4, Duration::from_millis(1));
        for _ in 0..100 {
            dispatch.observe(Duration::from_micros(5));
        }
        assert!(dispatch.inline_allowed());

        dispatch.observe(Duration::from_millis(1));
        assert!(!dispatch.inline_allowed());
        assert!(dispatch.try_inline().is_none());

        let deadline = dispatch.blocking_until.load(Ordering::Relaxed);
        assert!(
            deadline >= u64::try_from(SLOW_COOLDOWN.as_nanos()).unwrap_or(u64::MAX),
            "cooldown must last at least {SLOW_COOLDOWN:?}"
        );
        dispatch
            .blocking_until
            .store(dispatch.now_nanos(), Ordering::Relaxed);
        assert!(dispatch.inline_allowed(), "the cooldown must expire");
    }

    /// `serve` must actually time its inline resolutions and feed the result
    /// back into the dispatcher. An arithmetic-only test still passes when
    /// that wiring is missing.
    #[tokio::test]
    async fn serving_a_request_feeds_the_measured_latency_back() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("file.txt"), "0123456789")?;
        // Any completed resolution counts as slow at a zero threshold.
        let files = Arc::new(Files {
            root: std::fs::canonicalize(root.path())?,
            protected: None,
            dispatch: Arc::new(Dispatch::with_limits(4, Duration::ZERO)),
            budget: Arc::new(super::file_response::BodyBudget::new(
                super::file_response::STREAM_BUDGET,
            )),
        });
        assert!(files.dispatch.inline_allowed());

        let request = Request::builder().uri("/file.txt").body(Body::empty())?;
        let response = serve(Arc::clone(&files), request).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(
            !files.dispatch.inline_allowed(),
            "serve must report the resolution latency to the dispatcher"
        );
        Ok(())
    }
}
