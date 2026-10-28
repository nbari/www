use anyhow::Result;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt;
use std::path::Path;
use tower::ServiceExt;
use www::server;

async fn request(
    app: &Router,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Response> {
    let mut request = Request::builder().method(method).uri(url);
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    Ok(app.clone().oneshot(request.body(Body::empty())?).await?)
}

async fn text(response: Response) -> Result<String> {
    Ok(String::from_utf8(
        response.into_body().collect().await?.to_bytes().to_vec(),
    )?)
}

async fn app(root: &Path) -> Result<Router> {
    server::router(root.to_owned(), None).await
}

async fn protected_app(root: &Path, cache: &Path) -> Result<Router> {
    server::router(root.to_owned(), Some(cache.to_owned())).await
}

#[tokio::test]
async fn browse_sorted_escaped_files_and_follow_encoded_links() -> Result<()> {
    let root = tempfile::tempdir()?;
    for name in ["z.txt", ".hidden", "a & <b>.txt", "a?#% ü.txt"] {
        std::fs::write(root.path().join(name), name)?;
    }
    std::fs::create_dir(root.path().join("sub"))?;
    let app = app(root.path()).await?;
    let response = request(&app, "GET", "/", &[]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let listing = text(response).await?;
    assert!(listing.contains(".hidden"));
    assert!(listing.contains("a &amp; &lt;b&gt;.txt"));
    assert!(listing.contains("./sub/"));
    assert!(listing.find(".hidden") < listing.find("z.txt"));
    assert!(listing.contains("./a%3F%23%25%20%C3%BC.txt"));
    let response = request(&app, "GET", "/a%3F%23%25%20%C3%BC.txt", &[]).await?;
    assert_eq!(text(response).await?, "a?#% ü.txt");
    Ok(())
}

#[tokio::test]
async fn indexes_redirects_and_head() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("sub"))?;
    std::fs::write(root.path().join("sub/index.html"), "<h1>index</h1>")?;
    std::fs::write(root.path().join("myindex.html"), "ordinary file")?;
    let app = app(root.path()).await?;
    let response = request(&app, "GET", "/sub?x=1", &[]).await?;
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok()),
        Some("/sub/?x=1")
    );
    let response = request(&app, "GET", "/sub/index.html?x=1", &[]).await?;
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok()),
        Some("/sub/?x=1")
    );
    assert_eq!(
        text(request(&app, "GET", "/sub/", &[]).await?).await?,
        "<h1>index</h1>"
    );
    assert_eq!(
        text(request(&app, "GET", "/myindex.html", &[]).await?).await?,
        "ordinary file"
    );
    for url in ["/", "/sub/"] {
        let get = request(&app, "GET", url, &[]).await?;
        let head = request(&app, "HEAD", url, &[]).await?;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers().get("content-length"),
            get.headers().get("content-length")
        );
        assert_eq!(text(head).await?, "");
    }
    Ok(())
}

#[tokio::test]
async fn redirects_stay_on_origin_and_remove_file_trailing_slashes() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("example.com"))?;
    std::fs::write(root.path().join("example.com/index.html"), "index")?;
    std::fs::write(root.path().join("file.txt"), "file")?;
    let app = app(root.path()).await?;
    for (url, target) in [
        ("//example.com?x=1", "/example.com/?x=1"),
        ("//example.com/index.html?x=1", "/example.com/?x=1"),
        ("/file.txt/", "/file.txt"),
    ] {
        let response = request(&app, "GET", url, &[]).await?;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY, "{url}");
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok()),
            Some(target),
            "{url}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn directory_named_index_html_remains_browsable() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("index.html"))?;
    std::fs::write(root.path().join("index.html/child.txt"), "child")?;
    let app = app(root.path()).await?;
    let response = request(&app, "GET", "/index.html", &[]).await?;
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok()),
        Some("/index.html/")
    );
    assert!(
        text(request(&app, "GET", "/index.html/", &[]).await?)
            .await?
            .contains("child.txt")
    );
    Ok(())
}

#[tokio::test]
async fn file_with_trailing_slash_redirects_to_file() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file.txt"), "file")?;
    let app = app(root.path()).await?;
    let response = request(&app, "GET", "/file.txt/", &[]).await?;
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok()),
        Some("/file.txt")
    );
    Ok(())
}

#[tokio::test]
async fn ranges_conditionals_and_rejections() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file.txt"), "0123456789")?;
    let app = app(root.path()).await?;
    let full = request(&app, "GET", "/file.txt", &[]).await?;
    let modified = full
        .headers()
        .get("last-modified")
        .ok_or_else(|| anyhow::anyhow!("missing Last-Modified"))?
        .to_str()?;
    let not_modified =
        request(&app, "GET", "/file.txt", &[("if-modified-since", modified)]).await?;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    let partial = request(&app, "GET", "/file.txt", &[("range", "bytes=2-5")]).await?;
    assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        partial
            .headers()
            .get("content-range")
            .and_then(|h| h.to_str().ok()),
        Some("bytes 2-5/10")
    );
    assert_eq!(text(partial).await?, "2345");
    assert_eq!(
        request(&app, "GET", "/file.txt", &[("range", "bytes=99-")])
            .await?
            .status(),
        StatusCode::RANGE_NOT_SATISFIABLE
    );
    for url in [
        "/missing",
        "/../secret",
        "/%2e%2e/secret",
        "/%2Fetc/passwd",
        "/%00",
        "/%5csecret",
    ] {
        assert_eq!(
            request(&app, "GET", url, &[]).await?.status(),
            StatusCode::NOT_FOUND,
            "{url}"
        );
    }
    assert_eq!(
        request(&app, "POST", "/file.txt", &[]).await?.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn protect_certificate_cache_and_symlink_aliases() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let cache = root.path().join("certificates");
    let private = www::tls::cache::PrivateCache::open(cache.clone()).await?;
    std::fs::write(cache.join("key"), "private")?;
    std::fs::write(root.path().join("ordinary"), "public")?;
    symlink(cache.join("key"), root.path().join("key-alias"))?;
    symlink(&cache, root.path().join("cache-alias"))?;
    symlink(cache.join("key"), root.path().join("index.html"))?;
    let app = server::router(root.path().to_owned(), Some(private.directory().to_owned())).await?;
    for url in ["/certificates/key", "/key-alias", "/cache-alias/key", "/"] {
        assert_eq!(
            request(&app, "GET", url, &[]).await?.status(),
            StatusCode::NOT_FOUND,
            "{url}"
        );
    }
    std::fs::remove_file(root.path().join("index.html"))?;
    let listing = text(request(&app, "GET", "/", &[]).await?).await?;
    assert!(!listing.contains("certificates"));
    assert!(!listing.contains("key-alias"));
    assert!(!listing.contains("cache-alias"));
    assert!(listing.contains("ordinary"));
    assert!(
        server::router(private.directory().to_owned(), Some(root.path().to_owned()))
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn preserve_ordinary_symlinks() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let external = tempfile::NamedTempFile::new()?;
    let external_dir = tempfile::tempdir()?;
    std::fs::write(external.path(), "linked")?;
    std::fs::write(external_dir.path().join("inside.txt"), "inside")?;
    symlink(external.path(), root.path().join("link"))?;
    symlink(external_dir.path(), root.path().join("dir-link"))?;
    symlink(
        root.path().join("missing-target"),
        root.path().join("broken-link"),
    )?;
    let app = app(root.path()).await?;
    assert_eq!(
        text(request(&app, "GET", "/link", &[]).await?).await?,
        "linked"
    );
    let listing = text(request(&app, "GET", "/", &[]).await?).await?;
    assert!(listing.contains("<a href=\"./link\">link</a>"));
    assert!(listing.contains("<a href=\"./dir-link/\">dir-link/</a>"));
    assert!(!listing.contains("broken-link"));
    Ok(())
}

fn touch_past(path: &Path) -> Result<()> {
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
    std::fs::File::open(path)?.set_modified(old)?;
    Ok(())
}

/// Assert an If-Range request with `validator` yields the full body (200).
async fn assert_full_fallback(app: &Router, validator: &str) -> Result<()> {
    let response = request(
        app,
        "GET",
        "/file.txt",
        &[("range", "bytes=2-5"), ("if-range", validator)],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK, "if-range {validator}");
    assert_eq!(
        response.headers().get("content-range"),
        None,
        "if-range {validator}"
    );
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok()),
        Some("10"),
        "if-range {validator}"
    );
    assert_eq!(text(response).await?, "0123456789", "if-range {validator}");
    Ok(())
}

/// Assert an If-Range request with `validator` applies the range (206).
async fn assert_partial(app: &Router, validator: &str) -> Result<()> {
    let response = request(
        app,
        "GET",
        "/file.txt",
        &[("range", "bytes=2-5"), ("if-range", validator)],
    )
    .await?;
    assert_eq!(
        response.status(),
        StatusCode::PARTIAL_CONTENT,
        "if-range {validator}"
    );
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|h| h.to_str().ok()),
        Some("bytes 2-5/10"),
        "if-range {validator}"
    );
    assert_eq!(text(response).await?, "2345", "if-range {validator}");
    Ok(())
}

#[tokio::test]
async fn if_range_precedence_and_fallback_to_full() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file.txt"), "0123456789")?;
    touch_past(&root.path().join("file.txt"))?;
    let app = app(root.path()).await?;
    let full = request(&app, "GET", "/file.txt", &[]).await?;
    assert_eq!(full.status(), StatusCode::OK);
    let etag = full
        .headers()
        .get("etag")
        .ok_or_else(|| anyhow::anyhow!("missing ETag"))?
        .to_str()?
        .to_owned();
    let modified = full
        .headers()
        .get("last-modified")
        .ok_or_else(|| anyhow::anyhow!("missing Last-Modified"))?
        .to_str()?
        .to_owned();

    // Non-matching validators fall back to the full representation.
    for validator in [
        "\"stale-etag\"",
        "Sun, 01 Jan 1995 00:00:00 GMT",
        "Thu, 01 Jan 2099 00:00:00 GMT",
        &format!("W/{etag}"),
        "not-a-date",
        "garbage",
    ] {
        assert_full_fallback(&app, validator).await?;
    }

    // Matching validators (strong ETag or exact Last-Modified) apply the range.
    for validator in [&etag, &modified] {
        assert_partial(&app, validator).await?;
    }

    // Normal conditional precedence is unchanged by If-Range handling.
    let not_modified = request(
        &app,
        "GET",
        "/file.txt",
        &[
            ("if-range", &etag),
            ("if-none-match", &etag),
            ("range", "bytes=2-5"),
        ],
    )
    .await?;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

    // A MISMATCHED If-Range strips the Range (full-body path) but a MATCHING
    // If-None-Match still takes precedence and yields 304, not 200/206.
    let mismatch_then_match = request(
        &app,
        "GET",
        "/file.txt",
        &[
            ("if-range", "\"stale-etag\""),
            ("if-none-match", &etag),
            ("range", "bytes=2-5"),
        ],
    )
    .await?;
    assert_eq!(mismatch_then_match.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(text(mismatch_then_match).await?, "");
    let precondition_failed = request(
        &app,
        "GET",
        "/file.txt",
        &[
            ("if-range", &etag),
            ("if-match", "\"stale-etag\""),
            ("range", "bytes=2-5"),
        ],
    )
    .await?;
    assert_eq!(
        precondition_failed.status(),
        StatusCode::PRECONDITION_FAILED
    );
    Ok(())
}

#[tokio::test]
async fn head_range_ignored_with_conditionals_still_enforced() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file.txt"), "0123456789")?;
    touch_past(&root.path().join("file.txt"))?;
    let app = app(root.path()).await?;
    let full = request(&app, "GET", "/file.txt", &[]).await?;
    let etag = full
        .headers()
        .get("etag")
        .ok_or_else(|| anyhow::anyhow!("missing ETag"))?
        .to_str()?
        .to_owned();

    // HEAD never honors Range: 200 with the full content-length and bodyless.
    for range in ["bytes=2-5", "bytes=99-", "bytes=abc"] {
        let response = request(&app, "HEAD", "/file.txt", &[("range", range)]).await?;
        assert_eq!(response.status(), StatusCode::OK, "head range {range}");
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|h| h.to_str().ok()),
            Some("10"),
            "head range {range}"
        );
        assert_eq!(
            response.headers().get("content-range"),
            None,
            "head range {range}"
        );
        assert_eq!(text(response).await?, "", "head range {range}");
    }

    // Conditionals still apply to HEAD regardless of Range.
    let not_modified = request(
        &app,
        "HEAD",
        "/file.txt",
        &[("range", "bytes=2-5"), ("if-none-match", &etag)],
    )
    .await?;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(text(not_modified).await?, "");
    let precondition_failed = request(
        &app,
        "HEAD",
        "/file.txt",
        &[("range", "bytes=2-5"), ("if-match", "\"stale-etag\"")],
    )
    .await?;
    assert_eq!(
        precondition_failed.status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(text(precondition_failed).await?, "");
    Ok(())
}

#[tokio::test]
async fn multi_range_serves_full_and_single_range_errors_stay_416() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file.txt"), "0123456789")?;
    touch_past(&root.path().join("file.txt"))?;
    let app = app(root.path()).await?;

    // A syntactically valid multi-range request falls back to the full body.
    let response = request(&app, "GET", "/file.txt", &[("range", "bytes=0-1,3-4")]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-range"), None);
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok()),
        Some("10")
    );
    assert_eq!(text(response).await?, "0123456789");

    // Unsatisfiable and malformed single-range requests still reject with 416.
    for range in ["bytes=99-", "bytes=abc"] {
        let response = request(&app, "GET", "/file.txt", &[("range", range)]).await?;
        assert_eq!(
            response.status(),
            StatusCode::RANGE_NOT_SATISFIABLE,
            "range {range}"
        );
    }
    Ok(())
}

// APFS rejects invalid UTF-8 names when creating the fixture (EILSEQ).
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test]
async fn preserve_non_utf8_filenames() -> Result<()> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let root = tempfile::tempdir()?;
    let name = OsString::from_vec(vec![b'x', 0xff]);
    std::fs::write(root.path().join(name), "bytes")?;
    let app = app(root.path()).await?;
    assert_eq!(
        text(request(&app, "GET", "/x%FF", &[]).await?).await?,
        "bytes"
    );
    assert!(
        text(request(&app, "GET", "/", &[]).await?)
            .await?
            .contains("./x%FF")
    );
    Ok(())
}

/// An unreadable regular file must remain listed (listing needs no read
/// permission) while GET returns 403. Modes are restored after obtaining the
/// listing; skipped only when an independent probe proves DAC is bypassed.
#[cfg(unix)]
#[tokio::test]
async fn unreadable_file_stays_listed_but_get_is_forbidden() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    let secret = root.path().join("secret.txt");
    std::fs::write(&secret, "private")?;
    let mut perms = std::fs::metadata(&secret)?.permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&secret, perms)?;

    // Independent DAC probe: if std::fs can read the mode-0000 file, this
    // process bypasses DAC (root) and the test is not meaningful.
    if std::fs::read(&secret).is_ok() {
        let mut perms = std::fs::metadata(&secret)?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&secret, perms)?;
        return Ok(());
    }

    // Ordinary symlink alias to the unreadable regular file.
    std::os::unix::fs::symlink(&secret, root.path().join("alias.txt"))?;

    let app = app(root.path()).await?;
    // Obtain the listing while the file is still unreadable.
    let listing = text(request(&app, "GET", "/", &[]).await?).await?;
    // GET both the file and its symlink alias: 403, not 200/404.
    let get_secret = request(&app, "GET", "/secret.txt", &[]).await?;
    let get_alias = request(&app, "GET", "/alias.txt", &[]).await?;

    // Restore mode before assertions/cleanup.
    let mut perms = std::fs::metadata(&secret)?.permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&secret, perms)?;

    // Both the regular name and the symlink alias must be listed.
    assert!(
        listing.contains("secret.txt"),
        "unreadable file must be listed"
    );
    assert!(
        listing.contains("alias.txt"),
        "symlink to unreadable file must be listed"
    );
    assert_eq!(get_secret.status(), StatusCode::FORBIDDEN);
    assert_eq!(get_alias.status(), StatusCode::FORBIDDEN);
    Ok(())
}
/// Protected variant: an unreadable regular file and its ordinary symlink alias
/// both remain listed and both GETs are 403 (listing needs no read permission).
#[cfg(unix)]
#[tokio::test]
async fn protected_unreadable_file_and_symlink_alias_stay_listed() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    let cache = root.path().join("certificates");
    let _private = www::tls::cache::PrivateCache::open(cache.clone()).await?;
    let secret = root.path().join("secret.txt");
    std::fs::write(&secret, "private")?;
    std::os::unix::fs::symlink(&secret, root.path().join("alias.css"))?;
    let mut perms = std::fs::metadata(&secret)?.permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&secret, perms)?;

    if std::fs::read(&secret).is_ok() {
        let mut perms = std::fs::metadata(&secret)?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&secret, perms)?;
        return Ok(());
    }

    let app = protected_app(root.path(), &cache).await?;
    let listing = text(request(&app, "GET", "/", &[]).await?).await?;
    let get_secret = request(&app, "GET", "/secret.txt", &[]).await?;
    let get_alias = request(&app, "GET", "/alias.css", &[]).await?;

    let mut perms = std::fs::metadata(&secret)?.permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&secret, perms)?;

    assert!(
        listing.contains("secret.txt"),
        "unreadable file must be listed"
    );
    assert!(
        listing.contains("alias.css"),
        "symlink to unreadable file must be listed"
    );
    assert_eq!(get_secret.status(), StatusCode::FORBIDDEN);
    assert_eq!(get_alias.status(), StatusCode::FORBIDDEN);
    Ok(())
}

/// A Unix-domain socket path returns 404 (unsupported file type), not 500, for
/// both GET and HEAD on an unprotected router.
#[cfg(unix)]
#[tokio::test]
async fn unix_socket_path_returns_404() -> Result<()> {
    use std::os::unix::net::UnixListener;
    let root = tempfile::tempdir()?;
    let sock_path = root.path().join("svc.sock");
    let _listener = UnixListener::bind(&sock_path)?;
    let app = app(root.path()).await?;
    for method in ["GET", "HEAD"] {
        let response = request(&app, method, "/svc.sock", &[]).await?;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{method} socket must be 404"
        );
    }
    Ok(())
}

/// A Unix-domain socket path returns 404 on a cache-protected router too.
#[cfg(unix)]
#[tokio::test]
async fn unix_socket_path_returns_404_when_protected() -> Result<()> {
    use std::os::unix::net::UnixListener;
    let root = tempfile::tempdir()?;
    let cache = root.path().join("certificates");
    let _private = www::tls::cache::PrivateCache::open(cache.clone()).await?;
    let sock_path = root.path().join("svc.sock");
    let _listener = UnixListener::bind(&sock_path)?;
    let app = protected_app(root.path(), &cache).await?;
    for method in ["GET", "HEAD"] {
        let response = request(&app, method, "/svc.sock", &[]).await?;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{method} protected socket must be 404"
        );
    }
    Ok(())
}

/// A protected symlink's Content-Type comes from the ORIGINAL logical path
/// (alias.css), not the target extension.
#[cfg(unix)]
#[tokio::test]
async fn protected_symlink_mime_uses_logical_path() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let cache = root.path().join("certificates");
    let _private = www::tls::cache::PrivateCache::open(cache.clone()).await?;
    std::fs::write(root.path().join("target.txt"), "body")?;
    symlink(
        root.path().join("target.txt"),
        root.path().join("alias.css"),
    )?;
    let app = protected_app(root.path(), &cache).await?;
    let response = request(&app, "GET", "/alias.css", &[]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("text/css"),
        "MIME must come from the logical .css path"
    );
    Ok(())
}
