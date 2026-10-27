use crate::tls::{self, TlsMode, cache::PrivateCache};
use anyhow::{Context, Result, bail};
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
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

mod directory;

#[derive(Debug)]
pub struct ServerConfig {
    pub root: PathBuf,
    pub port: u16,
    pub tls: TlsMode,
}

#[derive(Clone)]
struct Files {
    root: PathBuf,
    protected: Option<PathBuf>,
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
        Some(path) => Some(
            tokio::fs::canonicalize(path)
                .await
                .context("cannot open protected cache")?,
        ),
        None => None,
    };
    if !tokio::fs::metadata(&root).await?.is_dir() {
        bail!("document root must be a directory");
    }
    if protected
        .as_ref()
        .is_some_and(|cache| root.starts_with(cache))
    {
        bail!("document root cannot be inside the certificate cache");
    }
    Ok(Router::new()
        .fallback(files)
        .with_state(Arc::new(Files { root, protected }))
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

/// Initialize and serve files until shutdown or a fatal transport failure.
///
/// # Errors
/// Returns invalid configuration, cache, filesystem, socket, TLS, or server errors.
pub async fn run(
    mut config: ServerConfig,
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
    let app = router(
        config.root,
        cache.as_ref().map(|cache| cache.directory().to_owned()),
    )
    .await?;
    let listener =
        bind(config.port).with_context(|| format!("cannot listen on port {}", config.port))?;
    tracing::info!(address = %listener.local_addr()?, "Listening");
    match config.tls {
        TlsMode::Http => {
            let handle = axum_server::Handle::new();
            let server = axum_server::from_tcp(listener)?
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
            let server = axum_server::from_tcp_rustls(listener, tls)?
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
