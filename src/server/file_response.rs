//! Authorized single-file responses built on `tower-http`'s `ServeDir`.
//!
//! After the caller authorizes and prepares one file handle ([`Opened`]), this
//! module streams ONLY that handle through a private per-request [`Backend`],
//! preserving `tower-http`'s correct `Range`/precondition handling while never
//! re-opening any pathname. The request URI is rewritten to a constant
//! synthetic UTF-8 path (`/file`) because `ServeDir` decodes the URI with
//! `decode_utf8`, which would reject raw non-UTF-8 filenames.

use super::fs::Opened;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use std::{
    future::Future,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower_http::services::fs::{Backend, DefaultServeDirFallback, File as TowerFile, ServeDir};

/// `ServeDir` constrained to our one-file backend.
type OneFileServeDir = ServeDir<DefaultServeDirFallback, OneFileBackend>;

/// Private per-request backend constrained to one prepared file handle.
///
/// The handle is consumed ONCE (`Arc<Mutex<Option<std File>>>`); `metadata` is
/// served from the cached fstat without any filesystem task. Both `open` and
/// `metadata` ignore the requested path and return the authorized handle.
#[derive(Clone)]
pub(super) struct OneFileBackend {
    file: Arc<Mutex<Option<std::fs::File>>>,
    metadata: std::fs::Metadata,
}

impl OneFileBackend {
    fn new(opened: Opened) -> Self {
        Self {
            file: Arc::new(Mutex::new(Some(opened.file))),
            metadata: opened.metadata,
        }
    }
}

/// A consumed or absent handle maps to `NotFound`.
fn gone() -> io::Error {
    io::Error::from(io::ErrorKind::NotFound)
}

/// Wrapper delegating `AsyncRead`/`AsyncSeek` to a Tokio file converted from
/// the prepared `std::fs::File`. Created at most once per request.
pub(super) struct PreparedFile {
    inner: tokio::fs::File,
    metadata: std::fs::Metadata,
}

impl tokio::io::AsyncRead for PreparedFile {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncSeek for PreparedFile {
    fn start_seek(mut self: std::pin::Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        std::pin::Pin::new(&mut self.inner).start_seek(position)
    }
    fn poll_complete(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<u64>> {
        std::pin::Pin::new(&mut self.inner).poll_complete(cx)
    }
}

impl TowerFile for PreparedFile {
    type Metadata = std::fs::Metadata;
    type MetadataFuture<'a> = std::future::Ready<io::Result<std::fs::Metadata>>;
    fn metadata(&self) -> Self::MetadataFuture<'_> {
        std::future::ready(Ok(self.metadata.clone()))
    }
}

impl Backend for OneFileBackend {
    type File = PreparedFile;
    type Metadata = std::fs::Metadata;
    type OpenFuture = std::future::Ready<io::Result<PreparedFile>>;
    type MetadataFuture = std::future::Ready<io::Result<std::fs::Metadata>>;

    fn open(&self, _path: PathBuf) -> Self::OpenFuture {
        let taken = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        std::future::ready(match taken {
            Some(file) => Ok(PreparedFile {
                inner: tokio::fs::File::from_std(file),
                metadata: self.metadata.clone(),
            }),
            None => Err(gone()),
        })
    }

    fn metadata(&self, _path: PathBuf) -> Self::MetadataFuture {
        std::future::ready(Ok(self.metadata.clone()))
    }
}

/// Override `Content-Type` on 200/206 only, preserving 416 error bodies.
fn set_content_type(response: &mut Response, original: &std::path::Path) {
    let status = response.status().as_u16();
    if status == 200 || status == 206 {
        let mime = mime_guess::from_path(original).first_or_octet_stream();
        if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
            response.headers_mut().insert(header::CONTENT_TYPE, value);
        }
    }
}

/// Decide whether the `If-Range` validator matches Tower's authoritative
/// validators (from a metadata-only HEAD probe). Returns `true` when the range
/// may be applied. Weak/malformed/multiple values never match.
fn if_range_matches(
    if_range_values: &[&HeaderValue],
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> bool {
    // Exactly one value; malformed or multiple => no match.
    let [single] = if_range_values else {
        return false;
    };
    let Ok(value) = single.to_str() else {
        return false;
    };
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if value.starts_with("W/") {
        // Weak validator never matches for If-Range.
        return false;
    }
    if value.starts_with('"') {
        // ETag form: strong, exact match against Tower's ETag.
        if !value.ends_with('"') {
            return false;
        }
        return etag == Some(value);
    }
    // HTTP-date form: exact parsed-date equality with Tower's Last-Modified.
    let (Some(probe_lm), Ok(parsed)) = (last_modified, httpdate::parse_http_date(value)) else {
        return false;
    };
    match httpdate::parse_http_date(probe_lm) {
        Ok(probe) => probe == parsed,
        Err(_) => false,
    }
}

/// Build a `ServeDir` over the single prepared handle with the synthetic URI.
fn build_service(backend: OneFileBackend, request: Request) -> (OneFileServeDir, Request) {
    let mut request = request;
    *request.uri_mut() = Uri::from_static("/file");
    let service = ServeDir::with_backend("", backend)
        .append_index_html_on_directories(false)
        .redirect_to_trailing_slash(false)
        .ignore_multi_range_requests(true);
    (service, request)
}

fn error_response(error: &io::Error) -> Response {
    let status = match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    status.into_response()
}

/// Serve the prepared handle, preserving `tower-http` `Range`/precondition
/// semantics. MIME is detected from `original`, the request's logical path.
///
/// One `Backend`/`ServeDir` is created once and used for both an optional
/// metadata-only HEAD probe (which never consumes the file) and the actual
/// request. For `GET` with `Range` + `If-Range`, the probe removes
/// `Range`/`If-Range` and all four conditional headers to obtain Tower's
/// authoritative `ETag`/`Last-Modified`; the range is applied only on a
/// strong/exact match, otherwise `Range` is stripped for a full-body fallback
/// while the original preconditions remain.
pub(super) fn serve(
    opened: Opened,
    original: &std::path::Path,
    mut request: Request,
) -> impl Future<Output = Response> + Send + '_ {
    let original = original.to_path_buf();
    let backend = OneFileBackend::new(opened);
    let is_get = request.method() == Method::GET;
    let is_head = request.method() == Method::HEAD;
    let mut if_range_raw: Vec<HeaderValue> = request
        .headers()
        .get_all(header::IF_RANGE)
        .iter()
        .cloned()
        .collect();
    let has_range = request.headers().contains_key(header::RANGE);

    async move {
        // HEAD never honors Range; conditionals are preserved.
        if is_head {
            request.headers_mut().remove(header::RANGE);
            request.headers_mut().remove(header::IF_RANGE);
        }

        // GET + Range + If-Range: metadata-only HEAD probe on the same backend.
        let mut strip_range = false;
        if is_get && has_range && !if_range_raw.is_empty() {
            // Metadata-only HEAD probe: no Range/If-Range, no conditionals.
            let mut probe_headers = request.headers().clone();
            probe_headers.remove(header::RANGE);
            probe_headers.remove(header::IF_RANGE);
            probe_headers.remove(header::IF_MATCH);
            probe_headers.remove(header::IF_NONE_MATCH);
            probe_headers.remove(header::IF_MODIFIED_SINCE);
            probe_headers.remove(header::IF_UNMODIFIED_SINCE);
            let mut probe = Request::new(Body::empty());
            *probe.method_mut() = Method::HEAD;
            *probe.uri_mut() = request.uri().clone();
            *probe.version_mut() = request.version();
            *probe.headers_mut() = probe_headers;
            let (mut probe_service, probe) = build_service(backend.clone(), probe);
            let (mut etag, mut last_modified) = (None, None);
            if let Ok(resp) = probe_service.try_call(probe).await {
                etag = resp
                    .headers()
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                last_modified = resp
                    .headers()
                    .get(header::LAST_MODIFIED)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
            }
            let refs: Vec<&HeaderValue> = if_range_raw.iter().collect();
            strip_range = !if_range_matches(&refs, etag.as_deref(), last_modified.as_deref());
        }

        if strip_range {
            request.headers_mut().remove(header::RANGE);
            request.headers_mut().remove(header::IF_RANGE);
            if_range_raw.clear();
        }

        let (mut service, request) = build_service(backend, request);
        match service.try_call(request).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                let mut response = Response::from_parts(parts, Body::new(body));
                set_content_type(&mut response, &original);
                response
            }
            Err(error) => error_response(&error),
        }
    }
}
