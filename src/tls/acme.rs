use anyhow::{Context, Result, bail};
use axum::Router;
use axum_server::Handle;
use axum_server::accept::Accept;
use futures_util::{StreamExt, future::BoxFuture};
use rustls_acme::AcmeConfig;
use std::{future::Future, io, net::TcpListener, sync::Arc, time::Duration};

pub(crate) fn install_provider() -> Result<(), Arc<rustls_acme::rustls::crypto::CryptoProvider>> {
    rustls_acme::rustls::crypto::ring::default_provider().install_default()
}

#[derive(Clone)]
struct HandshakeTimeout<I, A> {
    inner: I,
    tls: A,
    duration: Duration,
}

impl<I, S, A> Accept<tokio::net::TcpStream, S> for HandshakeTimeout<I, A>
where
    I: Accept<tokio::net::TcpStream, S>,
    A: Accept<I::Stream, I::Service> + Clone + Send + 'static,
    I::Future: Send + 'static,
    A::Future: Send + 'static,
{
    type Stream = A::Stream;
    type Service = A::Service;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let inner = self.inner.accept(stream, service);
        let tls = self.tls.clone();
        let duration = self.duration;
        Box::pin(async move {
            let (stream, service) = inner.await?;
            tokio::time::timeout(duration, tls.accept(stream, service))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
        })
    }
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serve both ACME TLS-ALPN challenges and normal HTTPS connections on one listener.
///
/// The state task must be polled even when no HTTP clients are connected: it drives
/// initial issuance, retries, and renewal. The configuration is injectable for local CAs.
///
/// # Errors
/// Returns listener or server failures, or unexpected termination of ACME processing.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    config: AcmeConfig<io::Error>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    serve_with_timeout(listener, app, config, shutdown, Duration::from_secs(10)).await
}

fn acme_tls_server<A>(
    listener: TcpListener,
    tls: A,
    handshake_timeout: Duration,
) -> io::Result<
    axum_server::Server<std::net::SocketAddr, HandshakeTimeout<crate::server::TcpAcceptor, A>>,
> {
    Ok(
        crate::server::tcp_server(listener)?.map(|inner| HandshakeTimeout {
            inner,
            tls,
            duration: handshake_timeout,
        }),
    )
}

async fn serve_with_timeout(
    listener: TcpListener,
    app: Router,
    config: AcmeConfig<io::Error>,
    shutdown: impl Future<Output = ()> + Send,
    handshake_timeout: Duration,
) -> Result<()> {
    let mut state = config.state();
    let mut tls = (*state.default_rustls_config()).clone();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = state.axum_acceptor(Arc::new(tls));
    let handle = Handle::new();
    let server = acme_tls_server(listener, tls, handshake_timeout)?
        .handle(handle.clone())
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>());
    tokio::pin!(server);
    let mut certificates = tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(event) => tracing::info!(?event, "ACME certificate event"),
                Err(error) => tracing::error!(%error, "ACME processing failed; will retry"),
            }
        }
    });
    // Also cancel certificate processing if a caller drops the serving future.
    let _abort_on_drop = AbortOnDrop(certificates.abort_handle());

    let result = tokio::select! {
        result = &mut server => result.context("HTTPS server failed"),
        result = &mut certificates => {
            handle.shutdown();
            let _ = server.await;
            result.context("ACME task failed")?;
            bail!("ACME processing stopped unexpectedly");
        }
        () = shutdown => {
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
            server.await.context("HTTPS shutdown failed")
        }
    };
    certificates.abort();
    let _ = certificates.await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncReadExt, sync::oneshot};

    #[tokio::test]
    async fn stalled_tls_handshake_is_closed_and_does_not_hold_shutdown() -> Result<()> {
        let _ = install_provider();
        let root = tempfile::tempdir()?;
        let cache = crate::tls::cache::PrivateCache::open(root.path().join("acme")).await?;
        let app = crate::server::router(root.path().to_owned(), Some(cache.directory().to_owned()))
            .await?;
        let listener = crate::server::bind(0)?;
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr()?.port()));
        let config = AcmeConfig::new(["localhost"])
            .cache(cache)
            .directory("https://127.0.0.1:1/directory");
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(serve_with_timeout(
            listener,
            app,
            config,
            async {
                let _ = shutdown.await;
            },
            Duration::from_millis(25),
        ));
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        let mut byte = [0_u8];
        let closed = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut byte)).await;
        let _ = stop.send(());
        // Abort the server on failure so a regression does not wait for its grace timeout.
        if closed.is_err() {
            task.abort();
            let _ = task.await;
            bail!("stalled TLS connection was not closed by the handshake timeout");
        }
        assert_eq!(closed??, 0);
        tokio::time::timeout(Duration::from_millis(300), task).await???;
        Ok(())
    }

    #[derive(Clone)]
    struct InspectNoDelay<A> {
        inner: A,
        observed: Arc<std::sync::atomic::AtomicBool>,
        invoked: Arc<tokio::sync::Notify>,
    }

    impl<S, A> Accept<tokio::net::TcpStream, S> for InspectNoDelay<A>
    where
        A: Accept<tokio::net::TcpStream, S>,
    {
        type Stream = A::Stream;
        type Service = A::Service;
        type Future = A::Future;

        fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
            self.observed.store(
                stream.nodelay().unwrap_or(false),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.invoked.notify_one();
            self.inner.accept(stream, service)
        }
    }

    #[tokio::test]
    async fn acme_tls_server_enables_tcp_nodelay_before_inner_tls_acceptor() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked = Arc::new(tokio::sync::Notify::new());
        let server = acme_tls_server(
            crate::server::bind(0)?,
            InspectNoDelay {
                inner: axum_server::accept::DefaultAcceptor::new(),
                observed: Arc::clone(&observed),
                invoked: Arc::clone(&invoked),
            },
            Duration::from_secs(1),
        )?;
        let acceptor = server.get_ref().clone();
        let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (stream, _) = listener.accept().await?;
        assert!(
            !stream.nodelay()?,
            "freshly accepted socket should start without TCP_NODELAY"
        );
        let notified = invoked.notified();
        let (_stream, ()) = acceptor.accept(stream, ()).await?;
        tokio::time::timeout(Duration::from_secs(1), notified).await?;
        let _client = client.await??;
        assert!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            "ACME TLS server must enable TCP_NODELAY before invoking inner TLS acceptor"
        );
        Ok(())
    }
}
