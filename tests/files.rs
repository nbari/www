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
    std::fs::write(external.path(), "linked")?;
    symlink(external.path(), root.path().join("link"))?;
    let app = app(root.path()).await?;
    assert_eq!(
        text(request(&app, "GET", "/link", &[]).await?).await?,
        "linked"
    );
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
