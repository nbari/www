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
struct HandshakeTimeout<A> {
    inner: A,
    duration: Duration,
}

impl<I, S, A> Accept<I, S> for HandshakeTimeout<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
{
    type Stream = A::Stream;
    type Service = A::Service;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = self.inner.accept(stream, service);
        let duration = self.duration;
        Box::pin(async move {
            tokio::time::timeout(duration, handshake)
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
    let acceptor = HandshakeTimeout {
        inner: state.axum_acceptor(Arc::new(tls)),
        duration: handshake_timeout,
    };
    let handle = Handle::new();
    let server = axum_server::from_tcp(listener)?
        .handle(handle.clone())
        .acceptor(acceptor)
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
}
