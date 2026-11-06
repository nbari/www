//! Wire-level protocol behaviour of a real server process.
//!
//! The in-process router tests cover HTTP semantics; these cover framing,
//! which only a real connection can exercise: a persistent HTTP/1.1
//! connection carrying several responses back to back, and HTTP/2, which the
//! server speaks with prior knowledge.

#![cfg(unix)]

use anyhow::{Context, Result, bail};
use std::{
    fmt::Write as _,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Bodies large enough to stream in several chunks, small enough to stay fast.
const STREAMED: usize = 600 * 1024;
const INLINED: usize = 2048;

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start(root: &Path) -> Result<Self> {
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let child = Command::new(env!("CARGO_BIN_EXE_www"))
            .args(["-q", "-p", &port.to_string(), "-r"])
            .arg(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let server = Self { child, port };
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(server);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!("server did not become ready")
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fixtures(root: &Path) -> Result<()> {
    std::fs::write(root.join("inline.bin"), vec![b'i'; INLINED])?;
    std::fs::write(root.join("streamed.bin"), vec![b's'; STREAMED])?;
    std::fs::write(root.join("empty.bin"), [])?;
    Ok(())
}

/// Read exactly one HTTP/1.1 response, returning its status, declared length
/// and body. Leaves anything after it unread so the next response can be
/// framed from the same stream.
fn read_response(stream: &mut TcpStream, buffered: &mut Vec<u8>) -> Result<(u16, usize, Vec<u8>)> {
    loop {
        if let Some(position) = buffered.windows(4).position(|w| w == b"\r\n\r\n") {
            let head =
                String::from_utf8_lossy(buffered.get(..position).unwrap_or_default()).to_string();
            let status: u16 = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .context("no status line")?
                .parse()?;
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())?
                })
                .context("no content-length")?;
            let body_start = position + 4;
            while buffered.len() < body_start + length {
                let mut chunk = vec![0_u8; 32 * 1024];
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    bail!("connection closed before the body was complete");
                }
                buffered.extend_from_slice(chunk.get(..read).unwrap_or_default());
            }
            let body = buffered
                .get(body_start..body_start + length)
                .unwrap_or_default()
                .to_vec();
            buffered.drain(..body_start + length);
            return Ok((status, length, body));
        }
        let mut chunk = vec![0_u8; 32 * 1024];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            bail!("connection closed before the headers were complete");
        }
        buffered.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
}

/// Several responses on one persistent connection must be framed exactly: a
/// `Content-Length` that disagrees with the bytes written would make the next
/// response start inside the previous body, which only shows up when a
/// connection is reused. Inlined, streamed and empty bodies take different
/// code paths, so all three are pipelined together.
#[test]
fn pipelined_responses_keep_exact_framing_on_one_connection() -> Result<()> {
    let root = tempfile::tempdir()?;
    fixtures(root.path())?;
    let server = Server::start(root.path())?;

    let mut stream = TcpStream::connect(("127.0.0.1", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let targets = [
        "/inline.bin",
        "/streamed.bin",
        "/empty.bin",
        "/inline.bin",
        "/streamed.bin",
    ];
    let mut request = String::new();
    for target in targets {
        let _ = write!(request, "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    }
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut buffered = Vec::new();
    for target in targets {
        let (status, length, body) = read_response(&mut stream, &mut buffered)?;
        let expected = match target {
            "/inline.bin" => INLINED,
            "/streamed.bin" => STREAMED,
            _ => 0,
        };
        assert_eq!(status, 200, "{target}");
        assert_eq!(length, expected, "{target} declared length");
        assert_eq!(body.len(), expected, "{target} body length");
        if let Some(&first) = body.first() {
            assert!(
                body.iter().all(|byte| *byte == first),
                "{target} body is corrupted"
            );
        }
    }
    assert!(
        buffered.is_empty(),
        "server wrote {} bytes beyond the last response",
        buffered.len()
    );
    Ok(())
}

/// The server answers HTTP/2 with prior knowledge. Streamed bodies carry no
/// transfer framing of their own there, so a length mismatch would surface as
/// a corrupt or short body rather than a closed connection.
#[tokio::test]
async fn http2_delivers_every_body_size_intact() -> Result<()> {
    let root = tempfile::tempdir()?;
    fixtures(root.path())?;
    let server = Server::start(root.path())?;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()?;

    for (target, expected) in [
        ("/inline.bin", INLINED),
        ("/streamed.bin", STREAMED),
        ("/empty.bin", 0),
    ] {
        let response = client.get(server.url(target)).send().await?;
        assert_eq!(response.status(), 200, "{target}");
        assert_eq!(response.version(), reqwest::Version::HTTP_2, "{target}");
        let declared = response.content_length();
        let body = response.bytes().await?;
        assert_eq!(body.len(), expected, "{target} body length");
        assert_eq!(
            declared,
            Some(u64::try_from(expected).unwrap_or_default()),
            "{target} content-length"
        );
    }

    // HEAD carries the full length with no body on HTTP/2 as well.
    let response = client.head(server.url("/streamed.bin")).send().await?;
    assert_eq!(
        response.content_length(),
        Some(u64::try_from(STREAMED).unwrap_or_default())
    );
    assert!(response.bytes().await?.is_empty());
    Ok(())
}

/// A range response over a reused connection must stop at the range, not run
/// to end of file, or the following response would be misframed.
#[test]
fn a_range_response_does_not_overrun_the_next_response() -> Result<()> {
    let root = tempfile::tempdir()?;
    fixtures(root.path())?;
    let server = Server::start(root.path())?;

    let mut stream = TcpStream::connect(("127.0.0.1", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.write_all(
        concat!(
            "GET /streamed.bin HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=10-109\r\n\r\n",
            "GET /inline.bin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .as_bytes(),
    )?;
    stream.flush()?;

    let mut buffered = Vec::new();
    let (status, length, body) = read_response(&mut stream, &mut buffered)?;
    assert_eq!(status, 206);
    assert_eq!(length, 100);
    assert_eq!(body.len(), 100);

    let (status, length, body) = read_response(&mut stream, &mut buffered)?;
    assert_eq!(status, 200);
    assert_eq!(length, INLINED);
    assert_eq!(body.len(), INLINED);
    assert_eq!(buffered.len(), 0);
    Ok(())
}
