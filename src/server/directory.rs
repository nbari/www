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
    io,
    os::unix::ffi::OsStringExt as _,
    path::{Component, Path, PathBuf},
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

fn relative_path(url: &str) -> Option<PathBuf> {
    let bytes = percent_decode_str(url.trim_start_matches('/')).collect::<Vec<_>>();
    if bytes.contains(&0) || bytes.contains(&b'\\') {
        return None;
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    let mut relative = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(name) => relative.push(name),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(relative)
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

/// Open a path through the protection (or unprotected) resolver on a blocking
/// worker. Policy/race denials map to 404; ordinary permission errors to 403.
async fn prepare(files: &Files, path: PathBuf) -> io::Result<fs::Opened> {
    let protected = files.protected.clone();
    tokio::task::spawn_blocking(move || match protected {
        Some(protected) => protected.open(&path),
        None => fs::open(&path),
    })
    .await
    .map_err(io::Error::other)?
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

pub(super) async fn serve(files: &Files, request: Request) -> Response {
    let url = request.uri().path().to_owned();
    let Some(relative) = relative_path(&url) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = files.root.join(relative);
    let opened = match prepare(files, path.clone()).await {
        Ok(opened) => opened,
        Err(err) => return error(&err),
    };
    let is_file = opened.metadata.is_file();
    let is_dir = opened.metadata.is_dir();
    if is_file && let Some(parent) = url.strip_suffix("/index.html") {
        return redirect(&request, &format!("{parent}/"));
    }
    if is_dir {
        if !url.ends_with('/') {
            return redirect(&request, &format!("{url}/"));
        }
        // Index path lookup is checked/opened independently; a policy denial
        // on the index is a 404 (not a missing index that falls back to 200).
        let index = path.join("index.html");
        match prepare(files, index.clone()).await {
            Ok(index_opened) if index_opened.metadata.is_file() => {
                return file_response::serve(index_opened, &index, request).await;
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound && !fs::is_denied(&err) => {}
            Err(err) => return error(&err),
        }
        return listing(files, &opened, &path, request.method() == Method::HEAD).await;
    }
    if !is_file {
        return StatusCode::NOT_FOUND.into_response();
    }
    if url.ends_with('/') {
        return redirect(&request, url.trim_end_matches('/'));
    }
    file_response::serve(opened, &path, request).await
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

async fn listing(files: &Files, opened: &fs::Opened, dir: &Path, head: bool) -> Response {
    let handle = match opened.file.try_clone() {
        Ok(handle) => handle,
        Err(err) => return error(&err),
    };
    let files_owned = files.clone();
    let dir_owned = dir.to_path_buf();
    let rows = match tokio::task::spawn_blocking(move || -> io::Result<Vec<Row>> {
        let entries = fs::list_entries(&handle)?;
        Ok(classify_listing(&files_owned, &dir_owned, entries))
    })
    .await
    {
        Ok(Ok(rows)) => rows,
        Ok(Err(err)) => return error(&err),
        Err(err) => return error(&io::Error::other(err)),
    };
    let mut html = String::from(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>Directory listing</title>\n<pre>\n",
    );
    for (name, directory) in rows {
        let suffix = if directory { "/" } else { "" };
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
