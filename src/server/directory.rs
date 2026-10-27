use super::Files;
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
    path::{Component, Path, PathBuf},
};
use tower_http::services::ServeFile;

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
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(String::from_utf8(bytes).ok()?);
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

async fn allowed(files: &Files, path: &Path) -> bool {
    if let Some(cache) = &files.protected {
        match tokio::fs::canonicalize(path).await {
            Ok(path) => !path.starts_with(cache),
            Err(_) => false,
        }
    } else {
        true
    }
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
    let url = request.uri().path();
    let Some(relative) = relative_path(url) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = files.root.join(relative);
    if !allowed(files, &path).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(err) => return error(&err),
    };
    if metadata.is_file()
        && let Some(parent) = url.strip_suffix("/index.html")
    {
        return redirect(&request, &format!("{parent}/"));
    }
    if metadata.is_dir() {
        if !url.ends_with('/') {
            return redirect(&request, &format!("{url}/"));
        }
        let index = path.join("index.html");
        if let Ok(metadata) = tokio::fs::metadata(&index).await
            && metadata.is_file()
        {
            if !allowed(files, &index).await {
                return StatusCode::NOT_FOUND.into_response();
            }
            return file(index, request).await;
        }
        return listing(files, &path, request.method() == Method::HEAD).await;
    }
    if !metadata.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if url.ends_with('/') {
        return redirect(&request, url.trim_end_matches('/'));
    }
    file(path, request).await
}

async fn file(path: PathBuf, request: Request) -> Response {
    match ServeFile::new(path).try_call(request).await {
        Ok(response) => response.map(Body::new),
        Err(err) => error(&err),
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn listing(files: &Files, path: &Path, head: bool) -> Response {
    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(entries) => entries,
        Err(err) => return error(&err),
    };
    let mut names = Vec::new();
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(err) => return error(&err),
        };
        if !allowed(files, &entry.path()).await {
            continue;
        }
        let metadata = match tokio::fs::metadata(entry.path()).await {
            Ok(metadata) if metadata.is_dir() || metadata.is_file() => metadata,
            _ => continue,
        };
        names.push((entry.file_name(), metadata.is_dir()));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut html = String::from(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>Directory listing</title>\n<pre>\n",
    );
    for (name, directory) in names {
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
