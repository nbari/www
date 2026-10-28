use crate::tls::{self, TlsMode, cache::PrivateCache};
use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

mod directory;
mod file_response;
mod fs;

#[derive(Debug)]
pub struct ServerConfig {
    pub root: PathBuf,
    pub port: u16,
    pub tls: TlsMode,
}

#[derive(Clone)]
struct Files {
    root: PathBuf,
    protected: Option<Arc<fs::Protected>>,
}

/// Build the HTTP service independently of CLI parsing and TLS transport.
///
/// # Errors
/// Returns an error if either directory cannot be resolved, the root is not a
/// directory, or the root lies inside the protected certificate cache.
pub async fn router(root: PathBuf, protected: Option<PathBuf>) -> Result<Router> {
    let root = tokio::fs::canonicalize(root)
        .await
        .context("cannot open document root")?;
    let protected = match protected {
        Some(path) => {
            let path = tokio::fs::canonicalize(path)
                .await
                .context("cannot open protected cache")?;
            Some(Arc::new(
                tokio::task::spawn_blocking({
                    let path = path.clone();
                    move || fs::Protected::new(&path)
                })
                .await
                .map_err(io::Error::other)??,
            ))
        }
        None => None,
    };
    router_with_protected(root, protected).await
}

/// Build the HTTP service from an already-prepared protection handle.
///
/// The docroot is validated through `protected.open()` inside a blocking setup
/// task so the actual pinned cache inode (or a descendant) is rejected even if
/// the cache directory was renamed; this is stronger than a path-string check.
///
/// # Errors
/// Returns an error if the root is not a directory or lies inside the cache.
async fn router_with_protected(
    root: PathBuf,
    protected: Option<Arc<fs::Protected>>,
) -> Result<Router> {
    let setup_protected = protected.clone();
    // Canonicalize and validate the docroot inside a blocking setup task; the
    // canonical root is stored in `Files.root` (no later canonicalization).
    let canonical_root = tokio::task::spawn_blocking(move || -> io::Result<PathBuf> {
        let canonical_root = std::fs::canonicalize(&root)?;
        let metadata = std::fs::metadata(&canonical_root)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "document root must be a directory",
            ));
        }
        if let Some(cache) = &setup_protected {
            // Reject the cache inode or a descendant via the resolver: this
            // catches a renamed cache whose pathname no longer matches. Only a
            // policy denial means the root is the pinned cache inode or a
            // descendant (even after a rename).
            if let Err(err) = cache.open(&canonical_root)
                && fs::is_denied(&err)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "document root cannot be inside the certificate cache",
                ));
            }
        }
        Ok(canonical_root)
    })
    .await
    .map_err(io::Error::other)??;
    Ok(Router::new()
        .fallback(files)
        .with_state(Arc::new(Files {
            root: canonical_root,
            protected,
        }))
        .layer(middleware::from_fn(log_request)))
}

async fn files(State(files): State<Arc<Files>>, request: Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return (StatusCode::METHOD_NOT_ALLOWED, [("allow", "GET, HEAD")]).into_response();
    }
    directory::serve(&files, request).await
}

async fn log_request(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let uri = request.uri().clone();
    let response = next.run(request).await;
    tracing::info!(?client, %uri, status = response.status().as_u16(), elapsed = ?start.elapsed(), "request");
    response
}

/// Bind all IPv4 and IPv6 interfaces when IPv6 is available.
///
/// # Errors
/// Returns socket setup or binding errors, including an unavailable or occupied port.
pub fn bind(port: u16) -> std::io::Result<TcpListener> {
    let (socket, address) = match Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
        Ok(socket) if socket.set_only_v6(false).is_ok() => {
            (socket, SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
        }
        _ => (
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        ),
    };
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Bind an explicit numeric address, or retain the all-interface default.
///
/// Explicit IPv6 addresses accept IPv6 only. Explicit bind failures never
/// fall back to another address or family.
///
/// # Errors
/// Returns socket setup and binding errors.
pub fn bind_address(address: Option<IpAddr>, port: u16) -> std::io::Result<TcpListener> {
    let Some(address) = address else {
        return bind(port);
    };
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(SocketAddr::new(address, port)))?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpAcceptor {
    nodelay: bool,
}

impl TcpAcceptor {
    #[must_use]
    pub(crate) fn from_env() -> Self {
        let disabled = std::env::var_os("WWW_BENCH_DISABLE_TCP_NODELAY")
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        Self { nodelay: !disabled }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for TcpAcceptor {
    type Stream = tokio::net::TcpStream;
    type Service = S;
    type Future = std::future::Ready<std::io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        if self.nodelay {
            axum_server::accept::NoDelayAcceptor::new().accept(stream, service)
        } else {
            axum_server::accept::DefaultAcceptor::new().accept(stream, service)
        }
    }
}

pub(crate) fn tcp_server(
    listener: TcpListener,
) -> std::io::Result<axum_server::Server<SocketAddr, TcpAcceptor>> {
    Ok(axum_server::from_tcp(listener)?.acceptor(TcpAcceptor::from_env()))
}

fn localhost_tls_server(
    listener: TcpListener,
    tls: axum_server::tls_rustls::RustlsConfig,
) -> std::io::Result<
    axum_server::Server<SocketAddr, axum_server::tls_rustls::RustlsAcceptor<TcpAcceptor>>,
> {
    Ok(tcp_server(listener)?
        .map(|acceptor| axum_server::tls_rustls::RustlsAcceptor::new(tls).acceptor(acceptor)))
}

/// Build the router from an optional `PrivateCache`, pinning protection to the
/// cache's EXACT held directory handle (no pathname re-open). Used by `run()`
/// and the shared-pin regression so both exercise identical wiring.
async fn router_from_cache(
    root: PathBuf,
    cache: Option<&crate::tls::cache::PrivateCache>,
) -> Result<Router> {
    let protected = match cache {
        Some(cache) => {
            let canonical = cache.directory().to_path_buf();
            let handle = cache.directory_handle();
            // Pin protection to the exact held handle inside a blocking task.
            let protected =
                tokio::task::spawn_blocking(move || fs::Protected::from_handle(canonical, handle))
                    .await
                    .map_err(io::Error::other)??;
            Some(Arc::new(protected))
        }
        None => None,
    };
    router_with_protected(root, protected).await
}

/// Initialize and serve files until shutdown or a fatal transport failure.
///
/// # Errors
/// Returns invalid configuration, cache, filesystem, socket, TLS, or server errors.
pub async fn run(config: ServerConfig, shutdown: impl Future<Output = ()> + Send) -> Result<()> {
    run_bound(config, None, shutdown).await
}

/// Initialize and serve files on an optional explicit address.
///
/// # Errors
/// Returns invalid configuration, cache, filesystem, socket, TLS, or server errors.
pub async fn run_bound(
    mut config: ServerConfig,
    address: Option<IpAddr>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    let _ = tls::acme::install_provider();
    let cache = if let TlsMode::Acme(options) = &mut config.tls {
        options.domain = tls::normalize_domain(&options.domain)?;
        Some(
            PrivateCache::open(options.cache_dir.clone())
                .await
                .context("cannot open certificate cache")?,
        )
    } else {
        None
    };
    let app = router_from_cache(config.root, cache.as_ref()).await?;
    let listener = bind_address(address, config.port)
        .with_context(|| format!("cannot listen on port {}", config.port))?;
    tracing::info!(address = %listener.local_addr()?, "Listening");
    match config.tls {
        TlsMode::Http => {
            let handle = axum_server::Handle::new();
            let server = tcp_server(listener)?
                .handle(handle.clone())
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            tokio::pin!(server);
            tokio::select! {
                result = &mut server => result.context("HTTP server failed"),
                () = shutdown => {
                    handle.graceful_shutdown(Some(Duration::from_secs(10)));
                    server.await.context("HTTP shutdown failed")
                }
            }
        }
        TlsMode::Localhost => {
            let tls = tls::localhost::config().await?;
            let handle = axum_server::Handle::new();
            let server = localhost_tls_server(listener, tls)?
                .handle(handle.clone())
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            tokio::pin!(server);
            tokio::select! {
                result = &mut server => result.context("HTTPS server failed"),
                () = shutdown => {
                    handle.graceful_shutdown(Some(Duration::from_secs(10)));
                    server.await.context("HTTPS shutdown failed")
                }
            }
        }
        TlsMode::Acme(options) => {
            let cache = cache.context("ACME cache not initialized")?;
            let acme = rustls_acme::AcmeConfig::new([options.domain])
                .cache(cache)
                .directory_lets_encrypt(!options.staging);
            tls::acme::serve(listener, app, acme, shutdown).await
        }
    }
}

/// Register handlers before opening the listener, so registration errors are fatal.
///
/// # Errors
/// Returns an error if SIGINT or SIGTERM registration fails on Unix.
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt =
            signal(SignalKind::interrupt()).context("cannot install SIGINT handler")?;
        let mut terminate =
            signal(SignalKind::terminate()).context("cannot install SIGTERM handler")?;
        Ok(async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "signal handler failed");
                std::future::pending::<()>().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_server::accept::Accept;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone)]
    struct InspectNoDelay<A> {
        inner: A,
        observed: Arc<AtomicBool>,
        invoked: Arc<tokio::sync::Notify>,
    }

    impl<S, A> Accept<tokio::net::TcpStream, S> for InspectNoDelay<A>
    where
        A: Accept<tokio::net::TcpStream, S, Stream = tokio::net::TcpStream>,
        A::Future: Send + 'static,
    {
        type Stream = tokio::net::TcpStream;
        type Service = A::Service;
        type Future = futures_util::future::BoxFuture<
            'static,
            std::io::Result<(Self::Stream, Self::Service)>,
        >;

        fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
            let inner = self.inner.accept(stream, service);
            let observed = Arc::clone(&self.observed);
            let invoked = Arc::clone(&self.invoked);
            Box::pin(async move {
                let (stream, service) = inner.await?;
                observed.store(stream.nodelay().unwrap_or(false), Ordering::SeqCst);
                invoked.notify_one();
                Ok((stream, service))
            })
        }
    }

    #[tokio::test]
    async fn plain_http_server_enables_tcp_nodelay_on_accepted_streams() -> Result<()> {
        let listener = bind(0)?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, listener.local_addr()?.port()));
        let observed = Arc::new(AtomicBool::new(false));
        let invoked = Arc::new(tokio::sync::Notify::new());
        let handle = axum_server::Handle::new();
        let observed_probe = Arc::clone(&observed);
        let invoked_probe = Arc::clone(&invoked);
        let server = tcp_server(listener)?
            .map(move |inner| InspectNoDelay {
                inner,
                observed: observed_probe,
                invoked: invoked_probe,
            })
            .handle(handle.clone())
            .serve(Router::new().into_make_service());
        let task = tokio::spawn(server);
        let notified = invoked.notified();
        let _client = tokio::net::TcpStream::connect(address).await?;
        tokio::time::timeout(Duration::from_secs(1), notified).await?;
        handle.shutdown();
        task.await??;
        assert!(
            observed.load(Ordering::SeqCst),
            "plain HTTP server must enable TCP_NODELAY on accepted TCP streams"
        );
        Ok(())
    }

    #[tokio::test]
    async fn localhost_tls_server_enables_tcp_nodelay_before_tls_handshake() -> Result<()> {
        let _ = tls::acme::install_provider();
        let tls = tls::localhost::config().await?;
        let server = localhost_tls_server(bind(0)?, tls)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = server.get_ref().clone();
        let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (stream, _) = listener.accept().await?;
        assert!(
            !stream.nodelay()?,
            "freshly accepted socket should start without TCP_NODELAY"
        );
        let raw_socket = stream.into_std()?;
        let probe_socket = raw_socket.try_clone()?;
        let stream = tokio::net::TcpStream::from_std(raw_socket)?;
        let mut accept_future = std::pin::pin!(acceptor.accept(stream, ()));
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(
            accept_future.as_mut().poll(&mut cx).is_pending(),
            "TLS handshake should remain pending while client sends no ClientHello"
        );
        let _client = client.await??;
        assert!(
            probe_socket.nodelay()?,
            "localhost TLS server must enable TCP_NODELAY before starting the TLS handshake"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_acceptor_toggles_socket_nodelay_for_benchmark_comparison() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;

        let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (stream, _) = listener.accept().await?;
        let (stream, ()) = TcpAcceptor { nodelay: false }.accept(stream, ()).await?;
        let _client = client.await??;
        assert!(!stream.nodelay()?);

        let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (stream, _) = listener.accept().await?;
        let (stream, ()) = TcpAcceptor { nodelay: true }.accept(stream, ()).await?;
        let _client = client.await??;
        assert!(stream.nodelay()?);
        Ok(())
    }

    /// Shared-pin regression: the cache is opened, its pathname renamed and
    /// replaced, and protection is built from its exact held handle. Even after
    /// the cache directory is moved into the public tree (so the configured
    /// path now refers elsewhere), stored certificate/account files and cache
    /// listings stay blocked via the router (GET/HEAD/listing).
    #[cfg(unix)]
    #[tokio::test]
    async fn shared_pin_cache_handle_stays_blocked_after_path_replacement() -> Result<()> {
        use crate::tls::cache::PrivateCache;
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use rustls_acme::{AccountCache, CertCache};
        use tower::ServiceExt;

        let root = tempfile::tempdir()?;
        let cache_path = root.path().join("acme");
        let cache = PrivateCache::open(cache_path.clone()).await?;
        let domains = vec!["example.com".to_owned()];
        cache
            .store_cert(&domains, "production", b"secret-cert")
            .await?;
        cache
            .store_account(&[], "production", b"secret-account")
            .await?;

        // Derive the real SHA-256 key filenames by observing prior stores.
        let mut cert_key = None;
        let mut account_key = None;
        for entry in std::fs::read_dir(&cache_path)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with("cert-") {
                cert_key = Some(name);
            } else if name.starts_with("account-") {
                account_key = Some(name);
            }
        }
        let cert_key = cert_key.ok_or_else(|| anyhow::anyhow!("missing cert key"))?;
        let account_key = account_key.ok_or_else(|| anyhow::anyhow!("missing account key"))?;
        assert_eq!(std::fs::read(cache_path.join(&cert_key))?, b"secret-cert");
        assert_eq!(
            std::fs::read(cache_path.join(&account_key))?,
            b"secret-account"
        );

        // Rename the cache path aside and move the held cache directory into
        // the public tree so its entries are reachable under root; the
        // configured path now refers elsewhere.
        let aside = root.path().join("acme-aside");
        std::fs::rename(&cache_path, &aside)?;
        std::fs::create_dir_all(&cache_path)?;
        let public_cache = root.path().join("moved");
        std::fs::rename(&aside, &public_cache)?;
        std::fs::write(public_cache.join("decoy.txt"), "decoy")?;

        // Use the SAME router construction as production run().
        let app = router_from_cache(root.path().to_path_buf(), Some(&cache)).await?;

        // GET + HEAD the exact stored cert and account URLs: blocked (404),
        // not served. If protection were disabled these would return the
        // secret bytes with 200.
        for (method, key) in [
            ("GET", cert_key.as_str()),
            ("HEAD", cert_key.as_str()),
            ("GET", account_key.as_str()),
            ("HEAD", account_key.as_str()),
        ] {
            let uri = format!("/moved/{key}");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{method} {uri} must be blocked"
            );
        }

        // The held cache directory listing must not reveal any entry names.
        let listing = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/moved/")
                    .body(Body::empty())?,
            )
            .await?;
        assert_ne!(
            listing.status(),
            StatusCode::OK,
            "moved cache directory must not be listable"
        );
        Ok(())
    }

    /// Startup rejects a document root that IS the pinned cache inode even
    /// after the cache pathname was renamed away.
    #[cfg(unix)]
    #[tokio::test]
    async fn startup_rejects_renamed_cache_as_docroot() -> Result<()> {
        use crate::tls::cache::PrivateCache;

        let root = tempfile::tempdir()?;
        let cache_path = root.path().join("acme");
        let cache = PrivateCache::open(cache_path.clone()).await?;
        std::fs::write(cache_path.join("secret"), "private")?;

        // Rename the cache pathname away; the pinned inode is unchanged.
        let moved = root.path().join("moved-cache");
        std::fs::rename(&cache_path, &moved)?;

        // Document root == the pinned cache inode must be rejected at startup.
        let result = router_from_cache(moved.clone(), Some(&cache)).await;
        assert!(result.is_err(), "renamed cache as docroot must be rejected");
        Ok(())
    }

    /// Startup rejects a document root that is a DESCENDANT of the pinned cache
    /// inode even after the cache pathname was renamed away.
    #[cfg(unix)]
    #[tokio::test]
    async fn startup_rejects_cache_descendant_as_docroot() -> Result<()> {
        use crate::tls::cache::PrivateCache;

        let root = tempfile::tempdir()?;
        let cache_path = root.path().join("acme");
        let cache = PrivateCache::open(cache_path.clone()).await?;
        std::fs::create_dir_all(cache_path.join("sub"))?;
        std::fs::write(cache_path.join("sub").join("secret"), "private")?;

        // Rename the cache pathname away; the pinned inode is unchanged.
        let moved = root.path().join("moved-cache");
        std::fs::rename(&cache_path, &moved)?;

        // Document root == a descendant of the pinned cache inode is rejected.
        let descendant = moved.join("sub");
        let result = router_from_cache(descendant, Some(&cache)).await;
        assert!(
            result.is_err(),
            "cache descendant as docroot must be rejected"
        );
        Ok(())
    }
}
