//! Real TLS-ALPN-01 issuance against Pebble, using ephemeral ports and generated test keys.
//! Run with: `PEBBLE_BIN=/path/to/pebble cargo test --test acme -- --ignored --nocapture`

use anyhow::{Context, Result, bail};
use rustls_acme::{
    AcmeConfig, CertCache,
    rustls::{ClientConfig, RootCertStore},
};
use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use www::{
    server,
    tls::{acme, cache::PrivateCache},
};

struct Pebble(Child);
impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn launch_server(
    cache: PrivateCache,
    root: &Path,
    listener: TcpListener,
    directory: &str,
    trust: Arc<ClientConfig>,
) -> Result<(oneshot::Sender<()>, tokio::task::JoinHandle<Result<()>>)> {
    let app = server::router(root.to_owned(), Some(cache.directory().to_owned())).await?;
    let config = AcmeConfig::new_with_client_config(["localhost"], trust)
        .cache(cache)
        .directory(directory);
    let (stop, shutdown) = oneshot::channel();
    let task = tokio::spawn(acme::serve(listener, app, config, async {
        let _ = shutdown.await;
    }));
    Ok((stop, task))
}

async fn stop_server(
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(12), task).await???;
    Ok(())
}

async fn cached(cache: &PrivateCache, directory: &str) -> Result<Vec<u8>> {
    cache
        .load_cert(&["localhost".to_owned()], directory)
        .await?
        .context("certificate was not cached")
}

struct Authority {
    pebble: Pebble,
    cert: rcgen::Certificate,
    api: std::net::SocketAddr,
    management: std::net::SocketAddr,
    log: tempfile::NamedTempFile,
}

impl Authority {
    fn start(root: &Path, port: u16) -> Result<Self> {
        let ca_address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let management_address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let key = rcgen::KeyPair::generate()?;
        let cert =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&key)?;
        let certificate = root.join("pebble.pem");
        let private_key = root.join("pebble.key");
        std::fs::write(&certificate, cert.pem())?;
        std::fs::write(&private_key, key.serialize_pem())?;
        let config_path = root.join("pebble.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&serde_json::json!({"pebble": {
                "listenAddress": ca_address.to_string(),
                "managementListenAddress": management_address.to_string(),
                "certificate": certificate,
                "privateKey": private_key,
                "tlsPort": port,
                "httpPort": port,
                "keyAlgorithm": "ecdsa",
                "retryAfter": {"authz": 1, "order": 1},
                "profiles": {"default": {"validityPeriod": 30}}
            }}))?,
        )?;
        let log = tempfile::NamedTempFile::new()?;
        let pebble = Pebble(
            Command::new(std::env::var_os("PEBBLE_BIN").unwrap_or_else(|| "pebble".into()))
                .arg("-config")
                .arg(config_path)
                .env("PEBBLE_VA_NOSLEEP", "1")
                .env("PEBBLE_WFE_NONCEREJECT", "0")
                .env("PEBBLE_AUTHZREUSE", "0")
                .stdout(log.reopen()?)
                .stderr(Stdio::inherit())
                .spawn()
                .context("install Pebble v2.8.0 and set PEBBLE_BIN")?,
        );
        Ok(Self {
            pebble,
            cert,
            api: ca_address,
            management: management_address,
            log,
        })
    }

    async fn clients(&self) -> Result<(String, Arc<ClientConfig>, reqwest::Client)> {
        let cert = &self.cert;
        let log = &self.log;
        let management_address = self.management;
        let directory = format!("https://localhost:{}/dir", self.api.port());
        let ca_client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_der(cert.der())?)
            .timeout(Duration::from_secs(2))
            .build()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if ca_client.get(&directory).send().await.is_ok() {
                break;
            }
            if Instant::now() > deadline {
                bail!(
                    "Pebble did not start: {}",
                    std::fs::read_to_string(log.path())?
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let issuer = ca_client
            .get(format!(
                "https://localhost:{}/roots/0",
                management_address.port()
            ))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(&issuer)?)
            .tls_info(true)
            .timeout(Duration::from_secs(2))
            .build()?;
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone())?;
        let trust = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(
                rustls_acme::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        Ok((directory, trust, client))
    }
}

#[tokio::test]
#[ignore = "requires Pebble v2.8.0 on PATH or PEBBLE_BIN"]
async fn issue_renew_restart_and_keep_serving_during_ca_failure() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("hello.txt"), "ACME works")?;
    let cache = PrivateCache::open(root.path().join("acme")).await?;
    let listener = server::bind(0)?;
    let port = listener.local_addr()?.port();
    let mut authority = Authority::start(root.path(), port)?;
    let (directory, trust, client) = authority.clients().await?;
    let (stop, task) = launch_server(
        cache.clone(),
        root.path(),
        listener,
        &directory,
        trust.clone(),
    )
    .await?;
    let url = format!("https://localhost:{port}/hello.txt");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(response) = client.get(&url).send().await {
            assert_eq!(response.error_for_status()?.text().await?, "ACME works");
            break;
        }
        if task.is_finished() || Instant::now() > deadline {
            bail!(
                "issuance failed: {}",
                std::fs::read_to_string(authority.log.path())?
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let original = cached(&cache, &directory).await?;
    // No HTTP requests while waiting: renewal must be driven by the background task.
    let deadline = Instant::now() + Duration::from_secs(35);
    while cached(&cache, &directory).await? == original {
        if Instant::now() > deadline {
            bail!("certificate was not renewed while idle");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let renewed = cached(&cache, &directory).await?;
    assert_eq!(
        client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?,
        "ACME works"
    );
    stop_server(stop, task).await?;

    // Restart with the CA offline: the account and current certificate must be reusable.
    authority.pebble.0.kill()?;
    authority.pebble.0.wait()?;
    let listener = server::bind(port)?;
    let (stop, task) =
        launch_server(cache.clone(), root.path(), listener, &directory, trust).await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(response) = client.get(&url).send().await {
            assert_eq!(response.error_for_status()?.text().await?, "ACME works");
            break;
        }
        if Instant::now() > deadline {
            bail!("cached certificate was not reused");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(cached(&cache, &directory).await?, renewed);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(
        client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?,
        "ACME works"
    );
    assert!(!task.is_finished(), "renewal error stopped HTTPS");
    stop_server(stop, task).await?;
    Ok(())
}
