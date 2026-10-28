#![cfg(unix)]

use anyhow::{Context, Result, bail};
use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    log: tempfile::NamedTempFile,
    port: u16,
}

impl Server {
    fn start(root: &Path, extra: &[&str]) -> Result<Self> {
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let log = tempfile::NamedTempFile::new()?;
        let child = Command::new(env!("CARGO_BIN_EXE_www"))
            .args(["-p", &port.to_string(), "-r"])
            .arg(root)
            .args(extra)
            .stdout(Stdio::null())
            .stderr(log.reopen()?)
            .spawn()?;
        Ok(Self { child, log, port })
    }

    fn logs(&self) -> Result<String> {
        Ok(std::fs::read_to_string(self.log.path())?)
    }

    async fn stop(&mut self, signal: &str) -> Result<()> {
        assert!(
            Command::new("kill")
                .args([signal, &self.child.id().to_string()])
                .status()?
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = self.child.try_wait()? {
                assert!(status.success(), "server failed: {}", self.logs()?);
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("server did not stop");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn ready(
    server: &mut Server,
    client: &reqwest::Client,
    url: &str,
) -> Result<reqwest::Response> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = server.child.try_wait()? {
            bail!("server exited {status}: {}", server.logs()?);
        }
        if let Ok(response) = client.get(url).send().await {
            return Ok(response);
        }
        if Instant::now() > deadline {
            bail!("server did not become ready: {}", server.logs()?);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

#[tokio::test]
async fn real_http_streams_and_exits_cleanly_on_sigterm() -> Result<()> {
    let root = tempfile::tempdir()?;
    let bytes = vec![0x5a; 2 * 1024 * 1024];
    std::fs::write(root.path().join("large.bin"), &bytes)?;
    let mut server = Server::start(root.path(), &[])?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()?;
    let port = server.port;
    let response = ready(
        &mut server,
        &client,
        &format!("http://127.0.0.1:{port}/large.bin"),
    )
    .await?;
    assert_eq!(response.bytes().await?.as_ref(), bytes.as_slice());
    server.stop("-TERM").await?;
    let logs = server.logs()?;
    assert!(logs.contains("Listening"));
    assert!(logs.contains("large.bin"));
    assert!(logs.contains("status=200"));
    Ok(())
}

#[tokio::test]
async fn localhost_certificate_has_working_sans_and_quiet_mode() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("hello.txt"), "hello TLS")?;
    let mut server = Server::start(root.path(), &["-s", "localhost", "-q"])?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .timeout(Duration::from_secs(5))
        .build()?;
    let port = server.port;
    let response = ready(
        &mut server,
        &client,
        &format!("https://localhost:{port}/hello.txt"),
    )
    .await?;
    let der = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .context("missing peer certificate")?;
    let trusted = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_der(der)?)
        .timeout(Duration::from_secs(5))
        .build()?;
    assert_eq!(response.text().await?, "hello TLS");
    for host in ["localhost", "127.0.0.1"] {
        let response = trusted
            .get(format!("https://{host}:{port}/hello.txt"))
            .send()
            .await?;
        assert_eq!(response.text().await?, "hello TLS");
    }
    if TcpListener::bind("[::1]:0").is_ok() {
        assert_eq!(
            trusted
                .get(format!("https://[::1]:{port}/hello.txt"))
                .send()
                .await?
                .text()
                .await?,
            "hello TLS"
        );
    }
    server.stop("-INT").await?;
    assert!(server.logs()?.is_empty(), "quiet logs: {}", server.logs()?);
    Ok(())
}

#[test]
fn startup_failures_are_visible_even_when_quiet() -> Result<()> {
    let root = tempfile::tempdir()?;
    let listener = www::server::bind(0)?;
    let output = Command::new(env!("CARGO_BIN_EXE_www"))
        .args(["-q", "-p", &listener.local_addr()?.port().to_string(), "-r"])
        .arg(root.path())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("cannot listen"));
    Ok(())
}

#[test]
fn explicit_listeners_bind_exact_addresses_without_fallback() -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let listener = www::server::bind_address(Some(v4), 0)?;
    assert_eq!(listener.local_addr()?.ip(), v4);
    let error = www::server::bind_address(Some(v4), listener.local_addr()?.port())
        .err()
        .context("occupied explicit IPv4 bind unexpectedly succeeded")?;
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);

    // Probe OS support independently; do not hide implementation failures.
    if let Ok(probe) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        drop(probe);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let listener = www::server::bind_address(Some(v6), 0)?;
        assert_eq!(listener.local_addr()?.ip(), v6);
        assert!(socket2::SockRef::from(&listener).only_v6()?);
        let error = www::server::bind_address(Some(v6), listener.local_addr()?.port())
            .err()
            .context("occupied explicit IPv6 bind unexpectedly succeeded")?;
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }
    let default = www::server::bind_address(None, 0)?;
    assert!(default.local_addr()?.ip().is_unspecified());
    if default.local_addr()?.is_ipv6() {
        assert!(!socket2::SockRef::from(&default).only_v6()?);
    }
    Ok(())
}

#[tokio::test]
async fn real_cli_serves_on_explicit_loopback_addresses() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("bound.txt"), "explicit listener")?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;
    for (address, host) in [("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")] {
        if address == "::1" && TcpListener::bind("[::1]:0").is_err() {
            continue;
        }
        let mut server = Server::start(root.path(), &["--bind", address])?;
        let port = server.port;
        let response = ready(
            &mut server,
            &client,
            &format!("http://{host}:{port}/bound.txt"),
        )
        .await?;
        assert_eq!(response.text().await?, "explicit listener");
        server.stop("-TERM").await?;
    }
    Ok(())
}

#[tokio::test]
async fn real_cli_explicit_occupied_bind_fails_without_fallback() -> Result<()> {
    let root = tempfile::tempdir()?;
    let listener = www::server::bind_address(Some("127.0.0.1".parse()?), 0)?;
    let log = tempfile::NamedTempFile::new()?;
    let port = listener.local_addr()?.port();
    let child = Command::new(env!("CARGO_BIN_EXE_www"))
        .args(["--bind", "127.0.0.1", "-p", &port.to_string(), "-r"])
        .arg(root.path())
        .stdout(Stdio::null())
        .stderr(log.reopen()?)
        .spawn()?;
    let mut server = Server { child, log, port };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = server.child.try_wait()? {
            assert!(!status.success());
            assert!(server.logs()?.contains("cannot listen"));
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("occupied explicit bind did not fail: {}", server.logs()?);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
