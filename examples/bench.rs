//! Local Rust HTTP/HTTPS benchmark runner comparing `TCP_NODELAY` enabled vs disabled.
//!
//! Run via `just bench`, `just bench-http`, or `just bench-https`.

use anyhow::{Context, Result, bail};
use ring::digest::{Context as DigestContext, SHA256};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const OHA_VERSION: &str = "1.16.0";
const VARIANTS: [&str; 2] = ["nodelay", "nagle"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Case {
    name: &'static str,
    path: &'static str,
    concurrency: usize,
    tls: bool,
    keepalive: bool,
}

const CASES: [Case; 14] = [
    Case {
        name: "http-small-c1",
        path: "/small.bin",
        concurrency: 1,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "http-small-c16",
        path: "/small.bin",
        concurrency: 16,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "http-small-c64",
        path: "/small.bin",
        concurrency: 64,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "http-small-c128",
        path: "/small.bin",
        concurrency: 128,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "http-medium-c16",
        path: "/medium.bin",
        concurrency: 16,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "http-large-c16",
        path: "/large.bin",
        concurrency: 16,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "http-listing-c16",
        path: "/listing/",
        concurrency: 16,
        tls: false,
        keepalive: true,
    },
    Case {
        name: "https-small-c1",
        path: "/small.bin",
        concurrency: 1,
        tls: true,
        keepalive: true,
    },
    Case {
        name: "https-small-c16",
        path: "/small.bin",
        concurrency: 16,
        tls: true,
        keepalive: true,
    },
    Case {
        name: "https-small-c64",
        path: "/small.bin",
        concurrency: 64,
        tls: true,
        keepalive: true,
    },
    Case {
        name: "https-small-c128",
        path: "/small.bin",
        concurrency: 128,
        tls: true,
        keepalive: true,
    },
    Case {
        name: "https-medium-c16",
        path: "/medium.bin",
        concurrency: 16,
        tls: true,
        keepalive: true,
    },
    Case {
        name: "https-large-c16",
        path: "/large.bin",
        concurrency: 16,
        tls: true,
        keepalive: true,
    },
    Case {
        name: "https-listing-c16",
        path: "/listing/",
        concurrency: 16,
        tls: true,
        keepalive: true,
    },
];

#[derive(Clone, Debug, PartialEq)]
struct SampleMetrics {
    case: String,
    variant: String,
    round: usize,
    requests: u64,
    errors: u64,
    seconds: f64,
    rps: f64,
    mib_per_second: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    response_bytes: u64,
    server_cpu_cores: f64,
    server_cpu_us_per_request: f64,
    sampled_peak_rss_mib: f64,
    client_wall_seconds: f64,
    raw_file: String,
    command: Vec<String>,
}

impl SampleMetrics {
    fn to_json(&self) -> Value {
        json!({
            "case": self.case,
            "variant": self.variant,
            "round": self.round,
            "requests": self.requests,
            "errors": self.errors,
            "seconds": self.seconds,
            "rps": self.rps,
            "mib_per_second": self.mib_per_second,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "response_bytes": self.response_bytes,
            "server_cpu_cores": self.server_cpu_cores,
            "server_cpu_us_per_request": self.server_cpu_us_per_request,
            "sampled_peak_rss_mib": self.sampled_peak_rss_mib,
            "client_wall_seconds": self.client_wall_seconds,
            "raw_file": self.raw_file,
            "command": self.command,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct VariantSummary {
    rps: f64,
    mib_per_second: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    server_cpu_cores: f64,
    server_cpu_us_per_request: f64,
    sampled_peak_rss_mib: f64,
    rps_range: [f64; 2],
    rounds: usize,
}

impl VariantSummary {
    fn to_json(&self) -> Value {
        json!({
            "rps": self.rps,
            "mib_per_second": self.mib_per_second,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "server_cpu_cores": self.server_cpu_cores,
            "server_cpu_us_per_request": self.server_cpu_us_per_request,
            "sampled_peak_rss_mib": self.sampled_peak_rss_mib,
            "rps_range": self.rps_range,
            "rounds": self.rounds,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct CaseSummary {
    variants: BTreeMap<String, VariantSummary>,
    nodelay_to_nagle_rps: Option<f64>,
}

impl CaseSummary {
    fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (variant, summary) in &self.variants {
            map.insert(variant.clone(), summary.to_json());
        }
        if let Some(ratio) = self.nodelay_to_nagle_rps {
            map.insert("nodelay_to_nagle_rps".to_owned(), json!(ratio));
        }
        Value::Object(map)
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let len = values.len();
    let mid = len / 2;
    if len % 2 == 1 {
        values.get(mid).copied().unwrap_or(0.0)
    } else {
        let low = values.get(mid.saturating_sub(1)).copied().unwrap_or(0.0);
        let high = values.get(mid).copied().unwrap_or(0.0);
        f64::midpoint(low, high)
    }
}

fn select_cases(mode: &str, names: &[String]) -> Result<Vec<Case>> {
    if !matches!(mode, "all" | "http" | "https") {
        bail!("invalid benchmark mode {mode:?}; expected all, http, or https");
    }
    for name in names {
        if !CASES.iter().any(|case| case.name == name) {
            bail!("unknown benchmark case {name:?}");
        }
    }
    let selected: Vec<Case> = CASES
        .into_iter()
        .filter(|case| {
            (mode == "all" || (mode == "https") == case.tls)
                && (names.is_empty() || names.iter().any(|n| n == case.name))
        })
        .collect();
    if selected.is_empty() {
        bail!("no benchmark cases matched mode={mode:?} and cases={names:?}");
    }
    Ok(selected)
}

#[allow(clippy::cast_precision_loss)]
fn validate_result(result: &Value, expected_size: u64) -> Result<SampleMetrics> {
    let summary = result.get("summary").context("oha JSON missing summary")?;
    let statuses = result
        .get("statusCodeDistribution")
        .and_then(Value::as_object)
        .context("oha JSON missing statusCodeDistribution")?;
    let errors_obj = result.get("errorDistribution").and_then(Value::as_object);
    let error_count: u64 = errors_obj.map_or(0, |map| map.values().filter_map(Value::as_u64).sum());
    let success_rate = summary
        .get("successRate")
        .and_then(Value::as_f64)
        .context("oha summary missing successRate")?;
    if error_count > 0
        || errors_obj.is_some_and(|map| !map.is_empty())
        || (success_rate - 1.0).abs() > f64::EPSILON
    {
        bail!(
            "load generator reported request errors: {errors_obj:?} (successRate={success_rate})"
        );
    }
    if statuses.len() != 1 {
        bail!("expected only HTTP 200 responses, got {statuses:?}");
    }
    let count = statuses
        .get("200")
        .and_then(Value::as_u64)
        .filter(|&c| c > 0)
        .with_context(|| format!("expected positive HTTP 200 count, got {statuses:?}"))?;
    let total_data = summary
        .get("totalData")
        .and_then(Value::as_u64)
        .context("oha summary missing integer totalData")?;
    if total_data != count.saturating_mul(expected_size) {
        bail!(
            "response body sizes ({total_data}) differ from verified fixture ({count} * {expected_size})"
        );
    }
    let total_secs = summary
        .get("total")
        .and_then(Value::as_f64)
        .context("oha summary missing total seconds")?;
    let reported_rps = summary
        .get("requestsPerSec")
        .and_then(Value::as_f64)
        .context("oha summary missing requestsPerSec")?;
    let latencies = result
        .get("latencyPercentiles")
        .context("oha JSON missing latencyPercentiles")?;
    let p50 = latencies
        .get("p50")
        .and_then(Value::as_f64)
        .context("oha JSON missing p50")?;
    let p95 = latencies
        .get("p95")
        .and_then(Value::as_f64)
        .context("oha JSON missing p95")?;
    let p99 = latencies
        .get("p99")
        .and_then(Value::as_f64)
        .context("oha JSON missing p99")?;

    if ![total_secs, reported_rps, p50, p95, p99]
        .into_iter()
        .all(|v| v.is_finite() && v >= 0.0)
        || total_secs <= 0.0
        || reported_rps <= 0.0
    {
        bail!("invalid timing measurements in oha output");
    }

    Ok(SampleMetrics {
        case: String::new(),
        variant: String::new(),
        round: 0,
        requests: count,
        errors: 0,
        seconds: total_secs,
        rps: (count as f64) / total_secs,
        mib_per_second: (total_data as f64) / total_secs / (1024.0 * 1024.0),
        p50_ms: p50 * 1000.0,
        p95_ms: p95 * 1000.0,
        p99_ms: p99 * 1000.0,
        response_bytes: expected_size,
        server_cpu_cores: 0.0,
        server_cpu_us_per_request: 0.0,
        sampled_peak_rss_mib: 0.0,
        client_wall_seconds: 0.0,
        raw_file: String::new(),
        command: Vec::new(),
    })
}

fn aggregate(samples: &[SampleMetrics]) -> BTreeMap<String, CaseSummary> {
    let mut grouped: BTreeMap<String, BTreeMap<String, Vec<&SampleMetrics>>> = BTreeMap::new();
    for sample in samples {
        grouped
            .entry(sample.case.clone())
            .or_default()
            .entry(sample.variant.clone())
            .or_default()
            .push(sample);
    }
    let mut summary = BTreeMap::new();
    for (name, variants) in grouped {
        if variants.is_empty() {
            continue;
        }
        let round_counts: BTreeSet<usize> = variants.values().map(Vec::len).collect();
        if round_counts.len() != 1 {
            continue;
        }
        let mut case_variants = BTreeMap::new();
        for (variant, rows) in variants {
            let rps_vals: Vec<f64> = rows.iter().map(|r| r.rps).collect();
            let min_rps = rps_vals.iter().copied().fold(f64::INFINITY, f64::min);
            let max_rps = rps_vals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            case_variants.insert(
                variant,
                VariantSummary {
                    rps: median(rps_vals),
                    mib_per_second: median(rows.iter().map(|r| r.mib_per_second).collect()),
                    p50_ms: median(rows.iter().map(|r| r.p50_ms).collect()),
                    p95_ms: median(rows.iter().map(|r| r.p95_ms).collect()),
                    p99_ms: median(rows.iter().map(|r| r.p99_ms).collect()),
                    server_cpu_cores: median(rows.iter().map(|r| r.server_cpu_cores).collect()),
                    server_cpu_us_per_request: median(
                        rows.iter().map(|r| r.server_cpu_us_per_request).collect(),
                    ),
                    sampled_peak_rss_mib: median(
                        rows.iter().map(|r| r.sampled_peak_rss_mib).collect(),
                    ),
                    rps_range: [min_rps, max_rps],
                    rounds: rows.len(),
                },
            );
        }
        let nodelay_to_nagle_rps = match (case_variants.get("nodelay"), case_variants.get("nagle"))
        {
            (Some(nd), Some(ng)) if ng.rps > 0.0 => Some(nd.rps / ng.rps),
            _ => None,
        };
        summary.insert(
            name,
            CaseSummary {
                variants: case_variants,
                nodelay_to_nagle_rps,
            },
        );
    }
    summary
}

fn parse_proc_stat(stat_content: &str, ticks_per_sec: f64, page_size: u64) -> Result<(f64, u64)> {
    let (_, after_comm) = stat_content
        .rsplit_once(')')
        .context("malformed /proc/<pid>/stat: missing ')'")?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let utime: u64 = fields
        .get(11)
        .context("missing utime in /proc/<pid>/stat")?
        .parse()?;
    let stime: u64 = fields
        .get(12)
        .context("missing stime in /proc/<pid>/stat")?
        .parse()?;
    let rss_pages: i64 = fields
        .get(21)
        .context("missing rss in /proc/<pid>/stat")?
        .parse()?;
    #[allow(clippy::cast_precision_loss)]
    let cpu_seconds = (utime.saturating_add(stime) as f64) / ticks_per_sec;
    let rss_bytes = u64::try_from(rss_pages.max(0))
        .unwrap_or(0)
        .saturating_mul(page_size);
    Ok((cpu_seconds, rss_bytes))
}

#[derive(Clone, Copy, Debug)]
struct SystemMetricsConfig {
    ticks_per_sec: f64,
    page_size: u64,
}

fn query_system_metrics_config() -> Result<SystemMetricsConfig> {
    resolve_executable("getconf")?;
    let ticks: f64 = capture("getconf", &["CLK_TCK"])
        .context("failed to query OS clock ticks via `getconf CLK_TCK`")?
        .parse()
        .context("invalid CLK_TCK from getconf")?;
    let page_size: u64 = capture("getconf", &["PAGESIZE"])
        .context("failed to query OS page size via `getconf PAGESIZE`")?
        .parse()
        .context("invalid PAGESIZE from getconf")?;
    if !ticks.is_finite() || ticks <= 0.0 || page_size == 0 {
        bail!("invalid OS metrics configuration: CLK_TCK={ticks}, PAGESIZE={page_size}");
    }
    Ok(SystemMetricsConfig {
        ticks_per_sec: ticks,
        page_size,
    })
}

fn process_usage(pid: u32, sys: SystemMetricsConfig) -> Result<(f64, u64)> {
    let stat_content = fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("cannot read /proc/{pid}/stat"))?;
    parse_proc_stat(&stat_content, sys.ticks_per_sec, sys.page_size)
}

fn parse_cpu_list(spec: &str) -> Result<Vec<usize>> {
    let mut cpus = BTreeSet::new();
    for part in spec.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: usize = start.parse()?;
            let end: usize = end.parse()?;
            if end < start {
                bail!("invalid CPU range {part:?}");
            }
            for cpu in start..=end {
                cpus.insert(cpu);
            }
        } else {
            cpus.insert(part.parse()?);
        }
    }
    if cpus.is_empty() {
        bail!("empty CPU affinity list");
    }
    Ok(cpus.into_iter().collect())
}

fn available_cpus() -> Result<Vec<usize>> {
    let status = fs::read_to_string("/proc/self/status")
        .context("benchmarks require Linux /proc/self/status for CPU affinity discovery")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
            return parse_cpu_list(rest);
        }
    }
    bail!("Cpus_allowed_list not found in /proc/self/status")
}

fn fixture_bytes(seed: u64, size: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut out = vec![0_u8; size];
    for chunk in out.chunks_mut(8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let word = state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
        for (dst, src) in chunk.iter_mut().zip(word) {
            *dst = src;
        }
    }
    out
}

fn fixture_tree(root: &Path) -> Result<()> {
    fs::write(root.join("small.bin"), fixture_bytes(1, 1024))?;
    fs::write(root.join("medium.bin"), fixture_bytes(2, 100 * 1024))?;
    fs::write(root.join("large.bin"), fixture_bytes(3, 4 * 1024 * 1024))?;
    let listing = root.join("listing");
    fs::create_dir(&listing)?;
    for index in 0..200 {
        fs::write(
            listing.join(format!("file-{index:03}.txt")),
            format!("Entry {index}\n"),
        )?;
    }
    Ok(())
}

fn extract_listing_names(html: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = html;
    while let Some(pos) = rest.find("href=\"") {
        let after = &rest[pos + 6..];
        if let Some(end) = after.find('"') {
            let href = &after[..end];
            let trimmed = href.trim_start_matches("./").trim_end_matches('/');
            if !trimmed.is_empty() {
                names.insert(trimmed.to_owned());
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    names
}

async fn verify_endpoint(url: &str, fixtures: &Path, case: Case) -> Result<u64> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(case.tls)
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client
        .get(url)
        .header("accept-encoding", "identity")
        .send()
        .await
        .with_context(|| format!("preflight GET failed for {url}"))?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("preflight request failed with HTTP {}", response.status());
    }
    let body = response.bytes().await?;
    if case.path == "/listing/" {
        let html = std::str::from_utf8(&body).context("directory listing is not valid UTF-8")?;
        let names = extract_listing_names(html);
        for index in 0..200 {
            let expected_name = format!("file-{index:03}.txt");
            if !names.contains(&expected_name) {
                bail!("directory listing is missing fixture entry {expected_name}");
            }
        }
    } else {
        let relative = case.path.trim_start_matches('/');
        let expected = fs::read(fixtures.join(relative))?;
        if body.as_ref() != expected.as_slice() {
            bail!("preflight response bytes differ from fixture {}", case.path);
        }
    }
    Ok(body.len() as u64)
}

fn pinned_command(cpus: &[usize], program: &str, args: &[String]) -> Vec<String> {
    let mut cpu_list = String::new();
    for (idx, cpu) in cpus.iter().enumerate() {
        if idx > 0 {
            cpu_list.push(',');
        }
        let _ = write!(cpu_list, "{cpu}");
    }
    let mut full = vec![
        "taskset".to_owned(),
        "--cpu-list".to_owned(),
        cpu_list,
        program.to_owned(),
    ];
    full.extend_from_slice(args);
    full
}

fn terminate_process_tree(child: &mut Child, grace: Duration) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    #[cfg(unix)]
    {
        let pgid = format!("-{}", child.id());
        let _ = Command::new("kill")
            .args(["-TERM", &pgid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(15));
        }
        let _ = Command::new("kill")
            .args(["-KILL", &pgid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug)]
struct InterruptedError;

impl std::fmt::Display for InterruptedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("benchmark interrupted by signal")
    }
}

impl std::error::Error for InterruptedError {}

struct BenchServer {
    child: Child,
    log_path: PathBuf,
}

impl BenchServer {
    fn start(
        binary: &Path,
        fixtures: &Path,
        case: Case,
        variant: &str,
        cpus: &[usize],
        log_path: PathBuf,
        interrupted: &AtomicBool,
    ) -> Result<(Self, String)> {
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let mut args = vec![
            "-q".to_owned(),
            "-r".to_owned(),
            fixtures.display().to_string(),
            "-p".to_owned(),
            port.to_string(),
        ];
        if case.tls {
            args.push("-s".to_owned());
            args.push("localhost".to_owned());
        }
        let full = pinned_command(cpus, &binary.display().to_string(), &args);
        let log_file = fs::File::create(&log_path)?;
        let log_err = log_file.try_clone()?;
        let mut cmd = Command::new("taskset");
        cmd.args(full.iter().skip(1))
            .env("TOKIO_WORKER_THREADS", cpus.len().to_string())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_err));
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        if variant == "nagle" {
            cmd.env("WWW_BENCH_DISABLE_TCP_NODELAY", "1");
        } else {
            cmd.env_remove("WWW_BENCH_DISABLE_TCP_NODELAY");
        }
        let child = cmd.spawn().context("cannot spawn benchmark server")?;
        let mut server = Self { child, log_path };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if interrupted.load(Ordering::SeqCst) {
                return Err(InterruptedError.into());
            }
            if let Some(status) = server.child.try_wait()? {
                let logs = fs::read_to_string(&server.log_path).unwrap_or_default();
                bail!("server exited early ({status}): {logs}");
            }
            if std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                break;
            }
            if Instant::now() > deadline {
                let logs = fs::read_to_string(&server.log_path).unwrap_or_default();
                bail!("server did not start within 15s: {logs}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let scheme = if case.tls { "https" } else { "http" };
        Ok((server, format!("{scheme}://127.0.0.1:{port}{}", case.path)))
    }
}

impl Drop for BenchServer {
    fn drop(&mut self) {
        terminate_process_tree(&mut self.child, Duration::from_secs(2));
    }
}

struct OhaClient {
    child: Child,
}

impl Drop for OhaClient {
    fn drop(&mut self) {
        terminate_process_tree(&mut self.child, Duration::from_millis(500));
    }
}

struct OhaRun<'a> {
    oha: &'a str,
    url: &'a str,
    case: Case,
    duration: f64,
    cpus: &'a [usize],
    prefix: &'a Path,
    expected_size: u64,
    count: Option<usize>,
    sys: SystemMetricsConfig,
    interrupted: &'a AtomicBool,
}
impl OhaRun<'_> {
    fn args(&self) -> Vec<String> {
        let mut args = vec![
            "--no-tui".to_owned(),
            "--output-format".to_owned(),
            "json".to_owned(),
            "--http-version".to_owned(),
            "1.1".to_owned(),
            "--disable-compression".to_owned(),
            "--wait-ongoing-requests-after-deadline".to_owned(),
            "--worker-threads".to_owned(),
            self.cpus.len().to_string(),
            "-t".to_owned(),
            "10s".to_owned(),
            "-c".to_owned(),
            self.case.concurrency.to_string(),
        ];
        if let Some(n) = self.count {
            args.push("-n".to_owned());
            args.push(n.to_string());
        } else {
            args.push("-z".to_owned());
            args.push(format!("{}s", self.duration));
        }
        if self.case.tls {
            args.push("--insecure".to_owned());
        }
        if !self.case.keepalive {
            args.push("--disable-keepalive".to_owned());
        }
        args.push(self.url.to_owned());
        args
    }
}

#[allow(clippy::cast_precision_loss)]
fn run_oha_sample(run: &OhaRun<'_>, server: &mut BenchServer) -> Result<SampleMetrics> {
    if run.interrupted.load(Ordering::SeqCst) {
        return Err(InterruptedError.into());
    }
    let full = pinned_command(run.cpus, run.oha, &run.args());
    let raw_path = run.prefix.with_extension("json");
    let err_path = run.prefix.with_extension("stderr");
    let out_file = fs::File::create(&raw_path)?;
    let err_file = fs::File::create(&err_path)?;

    let (cpu_before, mut peak_rss) = process_usage(server.child.id(), run.sys)?;
    let started = Instant::now();
    let mut cmd = Command::new("taskset");
    cmd.args(full.iter().skip(1))
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env("NO_PROXY", "127.0.0.1,localhost,::1")
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut client = OhaClient {
        child: cmd.spawn().context("cannot spawn oha load generator")?,
    };

    let timeout = Duration::from_secs_f64(run.duration + 20.0);
    loop {
        if run.interrupted.load(Ordering::SeqCst) {
            return Err(InterruptedError.into());
        }
        if let Some(status) = client.child.try_wait()? {
            if !status.success() {
                let err_text = fs::read_to_string(&err_path).unwrap_or_default();
                bail!("oha failed ({status}): {}", err_text.trim());
            }
            break;
        }
        if server.child.try_wait()?.is_some() {
            bail!("server exited unexpectedly during load test");
        }
        if started.elapsed() > timeout {
            bail!("load test timed out: {}", raw_path.display());
        }
        if let Ok((_, rss)) = process_usage(server.child.id(), run.sys) {
            peak_rss = peak_rss.max(rss);
        }
        thread::sleep(Duration::from_millis(25));
    }

    let elapsed = started.elapsed().as_secs_f64();
    let (cpu_after, rss_after) = process_usage(server.child.id(), run.sys)?;
    if server.child.try_wait()?.is_some() {
        bail!("server exited during load test completion");
    }
    peak_rss = peak_rss.max(rss_after);
    let raw_json: Value = serde_json::from_str(&fs::read_to_string(&raw_path)?)
        .with_context(|| format!("invalid JSON in {}", raw_path.display()))?;
    let mut metrics = validate_result(&raw_json, run.expected_size)?;
    let cpu_seconds = (cpu_after - cpu_before).max(0.0);
    metrics.server_cpu_cores = cpu_seconds / elapsed;
    metrics.server_cpu_us_per_request = cpu_seconds / (metrics.requests as f64) * 1e6;
    metrics.sampled_peak_rss_mib = (peak_rss as f64) / (1024.0 * 1024.0);
    metrics.client_wall_seconds = elapsed;
    raw_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .clone_into(&mut metrics.raw_file);
    metrics.command = full;
    Ok(metrics)
}

fn capture(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("cannot execute `{program}`"))?;
    if !output.status.success() {
        bail!(
            "`{program} {}` failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn resolve_executable(name_or_path: &str) -> Result<String> {
    let path = Path::new(name_or_path);
    if path.components().count() > 1 {
        if path.is_file() {
            return Ok(fs::canonicalize(path)?.display().to_string());
        }
        bail!("missing executable at {name_or_path}");
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(name_or_path);
            if candidate.is_file() {
                return Ok(fs::canonicalize(candidate)?.display().to_string());
            }
        }
    }
    bail!(
        "missing executable `{name_or_path}` on PATH (install with `just bench-tools` or pass --oha /path/to/oha)"
    )
}

fn sha256_file(path: &Path) -> Result<(u64, String)> {
    let bytes = fs::read(path)?;
    let mut ctx = DigestContext::new(&SHA256);
    ctx.update(&bytes);
    let digest = ctx.finish();
    let mut hex = String::with_capacity(64);
    for b in digest.as_ref() {
        let _ = write!(hex, "{b:02x}");
    }
    Ok((bytes.len() as u64, hex))
}

fn build_release_binary(output_dir: &Path) -> Result<PathBuf> {
    let bin_dir = output_dir.join("bin");
    fs::create_dir_all(&bin_dir)?;
    let log_file = fs::File::create(output_dir.join("build.log"))?;
    let log_err = log_file.try_clone()?;
    let status = Command::new("cargo")
        .args(["build", "--release", "--locked", "--bin", "www"])
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .status()
        .context("failed to run `cargo build --release --locked --bin www`")?;
    if !status.success() {
        bail!(
            "cargo build --release failed; see {}",
            output_dir.join("build.log").display()
        );
    }
    let metadata: Value = serde_json::from_str(&capture(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version=1"],
    )?)?;
    let target_dir = metadata
        .get("target_directory")
        .and_then(Value::as_str)
        .context("cargo metadata missing target_directory")?;
    let dest = bin_dir.join("www");
    fs::copy(Path::new(target_dir).join("release/www"), &dest)?;
    Ok(dest)
}

fn save_report(
    status: &str,
    metadata: &serde_json::Map<String, Value>,
    samples: &[SampleMetrics],
    output_dir: &Path,
) -> Result<()> {
    let summary = aggregate(samples);
    let mut root = metadata.clone();
    root.insert("status".to_owned(), json!(status));
    root.insert(
        "samples".to_owned(),
        Value::Array(samples.iter().map(SampleMetrics::to_json).collect()),
    );
    let mut summary_obj = serde_json::Map::new();
    for (k, v) in &summary {
        summary_obj.insert(k.clone(), v.to_json());
    }
    root.insert("summary".to_owned(), Value::Object(summary_obj));
    fs::write(
        output_dir.join("results.json"),
        format!("{}\n", serde_json::to_string_pretty(&Value::Object(root))?),
    )?;

    let mut csv = String::from(
        "case,variant,round,requests,errors,rps,mib_per_second,p50_ms,p95_ms,p99_ms,server_cpu_cores,server_cpu_us_per_request,sampled_peak_rss_mib\n",
    );
    for s in samples {
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}",
            s.case,
            s.variant,
            s.round,
            s.requests,
            s.errors,
            s.rps,
            s.mib_per_second,
            s.p50_ms,
            s.p95_ms,
            s.p99_ms,
            s.server_cpu_cores,
            s.server_cpu_us_per_request,
            s.sampled_peak_rss_mib
        );
    }
    fs::write(output_dir.join("samples.csv"), csv)?;

    let mut lines = vec![
        format!("Status: {status}"),
        "Medians across rounds; p50/p95/p99 are medians of per-round latency percentiles."
            .to_owned(),
        String::new(),
    ];
    let paired = summary.values().any(|s| s.nodelay_to_nagle_rps.is_some());
    if paired {
        lines.push(format!(
            "{:<22} {:>14} {:>13} {:>9} {:>13} {:>11} {:>11} {:>11}",
            "Case",
            "NODELAY req/s",
            "Nagle req/s",
            "Speedup",
            "NODELAY MiB/s",
            "NODELAY p50",
            "NODELAY p95",
            "Nagle p95"
        ));
        for (name, case_sum) in &summary {
            if let (Some(nd), Some(ng), Some(ratio)) = (
                case_sum.variants.get("nodelay"),
                case_sum.variants.get("nagle"),
                case_sum.nodelay_to_nagle_rps,
            ) {
                lines.push(format!(
                    "{name:<22} {:>14.0} {:>13.0} {:>8.2}x {:>13.2} {:>9.3}ms {:>9.3}ms {:>9.3}ms",
                    nd.rps, ng.rps, ratio, nd.mib_per_second, nd.p50_ms, nd.p95_ms, ng.p95_ms
                ));
            }
        }
    } else {
        lines.push(format!(
            "{:<22} {:>8} {:>12} {:>11} {:>9} {:>9} {:>9}",
            "Case", "Variant", "req/s", "MiB/s", "p50 ms", "p95 ms", "p99 ms"
        ));
        for (name, case_sum) in &summary {
            for (variant, m) in &case_sum.variants {
                lines.push(format!(
                    "{name:<22} {variant:>8} {:>12.0} {:>11.2} {:>9.3} {:>9.3} {:>9.3}",
                    m.rps, m.mib_per_second, m.p50_ms, m.p95_ms, m.p99_ms
                ));
            }
        }
    }
    fs::write(
        output_dir.join("summary.txt"),
        format!("{}\n", lines.join("\n")),
    )?;
    Ok(())
}

struct CliArgs {
    oha: String,
    mode: String,
    variants: String,
    duration: f64,
    warmup: f64,
    repeats: usize,
    server_cpus: Option<usize>,
    cases: Vec<String>,
    output: Option<PathBuf>,
}

fn parse_args() -> Result<CliArgs> {
    let mut oha = std::env::var("WWW_BENCH_OHA").unwrap_or_else(|_| "oha".to_owned());
    let mut mode = String::from("all");
    let mut variants = String::from("both");
    let mut duration = 2.0_f64;
    let mut warmup = 0.5_f64;
    let mut repeats = 3_usize;
    let mut server_cpus = None;
    let mut cases = Vec::new();
    let mut output = None;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--oha" => oha = iter.next().context("--oha requires a path or name")?,
            "--mode" => mode = iter.next().context("--mode requires all, http, or https")?,
            "--variants" => {
                variants = iter
                    .next()
                    .context("--variants requires both, nodelay, or nagle")?;
            }
            "--duration" => {
                duration = iter
                    .next()
                    .context("--duration requires seconds")?
                    .parse()?;
            }
            "--warmup" => {
                warmup = iter.next().context("--warmup requires seconds")?.parse()?;
            }
            "--repeats" => {
                repeats = iter.next().context("--repeats requires count")?.parse()?;
            }
            "--server-cpus" => {
                server_cpus = Some(
                    iter.next()
                        .context("--server-cpus requires count")?
                        .parse()?,
                );
            }
            "--case" => cases.push(iter.next().context("--case requires case name")?),
            "--output" => {
                output = Some(PathBuf::from(
                    iter.next().context("--output requires path")?,
                ));
            }
            other => bail!("unknown argument {other:?}"),
        }
    }
    if !duration.is_finite() || duration <= 0.0 || !warmup.is_finite() || warmup <= 0.0 {
        bail!("--duration and --warmup must be finite positive numbers");
    }
    if repeats < 1 {
        bail!("--repeats must be at least 1");
    }
    if !matches!(variants.as_str(), "both" | "nodelay" | "nagle") {
        bail!("--variants must be both, nodelay, or nagle");
    }
    Ok(CliArgs {
        oha,
        mode,
        variants,
        duration,
        warmup,
        repeats,
        server_cpus,
        cases,
        output,
    })
}

fn install_signal_watcher() -> Result<Arc<AtomicBool>> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&interrupted);
    let signal = www::server::shutdown_signal()?;
    tokio::spawn(async move {
        signal.await;
        flag.store(true, Ordering::SeqCst);
    });
    Ok(interrupted)
}

#[tokio::main]
async fn main() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("local benchmark runner requires Linux (/proc and taskset CPU pinning)");
    }
    let args = parse_args()?;
    let sys = query_system_metrics_config()?;
    let cpus = available_cpus()?;
    let server_cpu_count = args
        .server_cpus
        .unwrap_or_else(|| (cpus.len() / 2).clamp(1, 4));
    if server_cpu_count == 0 || server_cpu_count >= cpus.len() {
        bail!("at least one CPU each for server and load generator is required");
    }
    let oha = resolve_executable(&args.oha)?;
    for dep in ["taskset", "cargo", "git"] {
        resolve_executable(dep)?;
    }
    let oha_version = capture(&oha, &["--version"])?;
    if oha_version != format!("oha {OHA_VERSION}") {
        bail!("requires oha {OHA_VERSION} (got {oha_version:?}); run `just bench-tools`");
    }
    let selected_cases = select_cases(&args.mode, &args.cases)?;
    let active_variants: Vec<&str> = match args.variants.as_str() {
        "both" => VARIANTS.to_vec(),
        "nodelay" => vec!["nodelay"],
        "nagle" => vec!["nagle"],
        _ => unreachable!(),
    };

    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let output_dir = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("target/benchmarks/run-{epoch_ms}")));
    if output_dir.exists() {
        bail!(
            "benchmark output directory {} already exists; choose a fresh --output path",
            output_dir.display()
        );
    }
    fs::create_dir_all(&output_dir)?;
    let output_dir = fs::canonicalize(&output_dir)?;
    println!("Benchmark output: {}", output_dir.display());
    println!("Building optimized release binary (details in build.log)...");
    let binary = build_release_binary(&output_dir)?;
    let (bin_bytes, bin_sha256) = sha256_file(&binary)?;

    let (server_cpus, client_cpus) = cpus.split_at(server_cpu_count);
    let mut metadata = build_metadata(
        &args,
        sys,
        &oha_version,
        &active_variants,
        server_cpus,
        client_cpus,
        bin_bytes,
        &bin_sha256,
    )?;

    let mut samples = Vec::new();
    save_report("running", &metadata, &samples, &output_dir)?;
    let interrupted = install_signal_watcher()?;

    let run_result = execute_matrix(
        &args,
        sys,
        &interrupted,
        &oha,
        &binary,
        &selected_cases,
        &active_variants,
        server_cpus,
        client_cpus,
        &output_dir,
        &metadata,
        &mut samples,
    )
    .await;

    match run_result {
        Ok(()) => {
            save_report("complete", &metadata, &samples, &output_dir)?;
            print!("{}", fs::read_to_string(output_dir.join("summary.txt"))?);
            Ok(())
        }
        Err(err) => {
            let status = if err.downcast_ref::<InterruptedError>().is_some()
                || interrupted.load(Ordering::SeqCst)
            {
                "interrupted"
            } else {
                "failed"
            };
            metadata.insert("error".to_owned(), json!(err.to_string()));
            let _ = save_report(status, &metadata, &samples, &output_dir);
            if status == "interrupted" {
                std::process::exit(130);
            }
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_metadata(
    args: &CliArgs,
    sys: SystemMetricsConfig,
    oha_version: &str,
    active_variants: &[&str],
    server_cpus: &[usize],
    client_cpus: &[usize],
    bin_bytes: u64,
    bin_sha256: &str,
) -> Result<serde_json::Map<String, Value>> {
    let cpu_model = fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            line.strip_prefix("model name")?
                .split_once(':')
                .map(|(_, v)| v.trim().to_owned())
        })
        .unwrap_or_else(|| std::env::consts::ARCH.to_owned());
    let mut metadata = serde_json::Map::new();
    metadata.insert("cpu_model".to_owned(), json!(cpu_model));
    metadata.insert("server_cpus".to_owned(), json!(server_cpus));
    metadata.insert("client_cpus".to_owned(), json!(client_cpus));
    metadata.insert(
        "clock_ticks_per_second".to_owned(),
        json!(sys.ticks_per_sec),
    );
    metadata.insert("page_size_bytes".to_owned(), json!(sys.page_size));
    metadata.insert(
        "rust_commit".to_owned(),
        json!(capture("git", &["rev-parse", "HEAD"])?),
    );
    metadata.insert(
        "rust_worktree_status".to_owned(),
        json!(capture("git", &["status", "--porcelain"])?),
    );
    metadata.insert(
        "rust_version".to_owned(),
        json!(capture("rustc", &["--version"])?),
    );
    metadata.insert(
        "cargo_version".to_owned(),
        json!(capture("cargo", &["--version"])?),
    );
    metadata.insert("oha_version".to_owned(), json!(oha_version));
    metadata.insert(
        "rust_build_flags".to_owned(),
        json!(["--release", "--locked", "--bin", "www"]),
    );
    metadata.insert(
        "build".to_owned(),
        json!({ "bytes": bin_bytes, "sha256": bin_sha256 }),
    );
    metadata.insert("mode".to_owned(), json!(args.mode));
    metadata.insert("variants".to_owned(), json!(active_variants));
    metadata.insert("duration_seconds".to_owned(), json!(args.duration));
    metadata.insert("warmup_seconds".to_owned(), json!(args.warmup));
    metadata.insert("repeats".to_owned(), json!(args.repeats));
    Ok(metadata)
}

#[allow(clippy::too_many_arguments)]
async fn execute_matrix(
    args: &CliArgs,
    sys: SystemMetricsConfig,
    interrupted: &AtomicBool,
    oha: &str,
    binary: &Path,
    selected_cases: &[Case],
    active_variants: &[&str],
    server_cpus: &[usize],
    client_cpus: &[usize],
    output_dir: &Path,
    metadata: &serde_json::Map<String, Value>,
    samples: &mut Vec<SampleMetrics>,
) -> Result<()> {
    let fixtures = tempfile::tempdir()?;
    fixture_tree(fixtures.path())?;
    for repeat in 0..args.repeats {
        for (index, &case) in selected_cases.iter().enumerate() {
            let mut order = active_variants.to_vec();
            if order.len() > 1 && (repeat + index) % 2 == 1 {
                order.reverse();
            }
            for variant in order {
                if interrupted.load(Ordering::SeqCst) {
                    return Err(InterruptedError.into());
                }
                let prefix = output_dir.join(format!("{}-{}-{variant}", case.name, repeat + 1));
                println!("[{}/{}] {}: {variant}", repeat + 1, args.repeats, case.name);
                let (mut srv, url) = BenchServer::start(
                    binary,
                    fixtures.path(),
                    case,
                    variant,
                    server_cpus,
                    prefix.with_extension("server.log"),
                    interrupted,
                )?;
                let expected = verify_endpoint(&url, fixtures.path(), case).await?;
                let preflight_prefix =
                    output_dir.join(format!("{}-{}-{variant}-preflight", case.name, repeat + 1));
                run_oha_sample(
                    &OhaRun {
                        oha,
                        url: &url,
                        case,
                        duration: 1.0,
                        cpus: client_cpus,
                        prefix: &preflight_prefix,
                        expected_size: expected,
                        count: Some(1),
                        sys,
                        interrupted,
                    },
                    &mut srv,
                )?;
                let warmup_prefix =
                    output_dir.join(format!("{}-{}-{variant}-warmup", case.name, repeat + 1));
                run_oha_sample(
                    &OhaRun {
                        oha,
                        url: &url,
                        case,
                        duration: args.warmup,
                        cpus: client_cpus,
                        prefix: &warmup_prefix,
                        expected_size: expected,
                        count: None,
                        sys,
                        interrupted,
                    },
                    &mut srv,
                )?;
                let mut metrics = run_oha_sample(
                    &OhaRun {
                        oha,
                        url: &url,
                        case,
                        duration: args.duration,
                        cpus: client_cpus,
                        prefix: &prefix,
                        expected_size: expected,
                        count: None,
                        sys,
                        interrupted,
                    },
                    &mut srv,
                )?;
                case.name.clone_into(&mut metrics.case);
                variant.clone_into(&mut metrics.variant);
                metrics.round = repeat + 1;
                samples.push(metrics);
                save_report("running", metadata, samples, output_dir)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_oha_json() -> Value {
        json!({
            "summary": {
                "successRate": 1.0,
                "total": 2.0,
                "requestsPerSec": 5.0,
                "totalData": 10240
            },
            "statusCodeDistribution": {
                "200": 10
            },
            "errorDistribution": {},
            "latencyPercentiles": {
                "p50": 0.001,
                "p95": 0.002,
                "p99": 0.003
            }
        })
    }

    #[test]
    fn validate_result_preserves_units_and_rejects_errors_or_bad_bodies() -> Result<()> {
        let metrics = validate_result(&valid_oha_json(), 1024)?;
        assert!((metrics.rps - 5.0).abs() < f64::EPSILON);
        assert!((metrics.p50_ms - 1.0).abs() < f64::EPSILON);
        assert!((metrics.p95_ms - 2.0).abs() < f64::EPSILON);
        assert!((metrics.p99_ms - 3.0).abs() < f64::EPSILON);
        assert!((metrics.mib_per_second - 5.0 / 1024.0).abs() < f64::EPSILON);

        let mut http_err = valid_oha_json();
        http_err["statusCodeDistribution"] = json!({"404": 10});
        assert!(validate_result(&http_err, 1024).is_err());

        let mut body_err = valid_oha_json();
        body_err["summary"]["totalData"] = json!(10239);
        assert!(validate_result(&body_err, 1024).is_err());

        let mut aborted = valid_oha_json();
        aborted["errorDistribution"] = json!({"aborted due to deadline": 1});
        assert!(validate_result(&aborted, 1024).is_err());

        let mut zero_time = valid_oha_json();
        zero_time["summary"]["total"] = json!(0.0);
        assert!(validate_result(&zero_time, 1024).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_uses_medians_and_rejects_unequal_rounds() {
        let make = |variant: &str, val: f64| SampleMetrics {
            case: "http-small-c1".to_owned(),
            variant: variant.to_owned(),
            round: 1,
            requests: 10,
            errors: 0,
            seconds: 1.0,
            rps: val,
            mib_per_second: val,
            p50_ms: val,
            p95_ms: val,
            p99_ms: val,
            response_bytes: 1024,
            server_cpu_cores: val,
            server_cpu_us_per_request: val,
            sampled_peak_rss_mib: val,
            client_wall_seconds: 1.0,
            raw_file: String::new(),
            command: Vec::new(),
        };
        let samples = vec![
            make("nagle", 10.0),
            make("nagle", 20.0),
            make("nagle", 100.0),
            make("nodelay", 30.0),
            make("nodelay", 40.0),
            make("nodelay", 90.0),
        ];
        let summary = aggregate(&samples);
        let case = summary.get("http-small-c1");
        assert!(case.is_some());
        if let Some(case) = case {
            assert_eq!(case.nodelay_to_nagle_rps, Some(2.0));
            let nagle = case.variants.get("nagle");
            assert!(nagle.is_some_and(|n| n.rps_range == [10.0, 100.0] && n.rounds == 3));
        }

        let unequal = vec![
            make("nodelay", 10.0),
            make("nagle", 20.0),
            make("nodelay", 30.0),
        ];
        assert!(aggregate(&unequal).is_empty());
    }

    #[test]
    fn select_cases_and_fixtures_cover_required_matrix() -> Result<()> {
        let http = select_cases("http", &[])?;
        let https = select_cases("https", &[])?;
        assert!(http.iter().all(|c| !c.tls));
        assert!(https.iter().all(|c| c.tls));
        let concurrencies: BTreeSet<usize> = http.iter().map(|c| c.concurrency).collect();
        assert_eq!(concurrencies, BTreeSet::from([1, 16, 64, 128]));

        let tmp = tempfile::tempdir()?;
        fixture_tree(tmp.path())?;
        assert_eq!(fs::metadata(tmp.path().join("small.bin"))?.len(), 1024);
        assert_eq!(
            fs::metadata(tmp.path().join("medium.bin"))?.len(),
            100 * 1024
        );
        assert_eq!(
            fs::metadata(tmp.path().join("large.bin"))?.len(),
            4 * 1024 * 1024
        );
        assert_eq!(fs::read_dir(tmp.path().join("listing"))?.count(), 200);

        let names = extract_listing_names(
            "<pre><a href=\"./file-001.txt\">file-001.txt</a><a href=\"./sub/\">sub/</a></pre>",
        );
        assert!(names.contains("file-001.txt"));
        assert!(names.contains("sub"));
        Ok(())
    }

    #[test]
    fn proc_stat_and_cpu_list_parsers_handle_4k_and_64k_pages() -> Result<()> {
        let stat = "12345 (www worker) S 1 12345 12345 0 -1 4194304 500 0 0 0 150 50 0 0 20 0 4 0 1000 12345678 2048 18446744073709551615";
        let (cpu_secs, rss_4k) = parse_proc_stat(stat, 100.0, 4096)?;
        assert!((cpu_secs - 2.0).abs() < f64::EPSILON);
        assert_eq!(rss_4k, 2048 * 4096);

        let (cpu_secs_64k, rss_64k) = parse_proc_stat(stat, 100.0, 65536)?;
        assert!((cpu_secs_64k - 2.0).abs() < f64::EPSILON);
        assert_eq!(rss_64k, 2048 * 65536);

        if cfg!(target_os = "linux") {
            let sys = query_system_metrics_config()?;
            assert!(sys.ticks_per_sec > 0.0);
            assert!(sys.page_size >= 4096);
        }

        let cpus = parse_cpu_list("0-3, 6, 8-9")?;
        assert_eq!(cpus, vec![0, 1, 2, 3, 6, 8, 9]);
        Ok(())
    }

    fn shell_single_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[test]
    fn bench_server_drop_terminates_spawned_listener() -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }
        if let Ok(port_str) = std::env::var("WWW_TEST_DUMMY_SERVER_PORT") {
            let mut args = std::env::args();
            while let Some(arg) = args.next() {
                if arg == "-p"
                    && let Some(p) = args.next()
                {
                    let listener = TcpListener::bind(("127.0.0.1", p.parse::<u16>()?))?;
                    fs::write(&port_str, p)?;
                    for stream in listener.incoming() {
                        let _ = stream;
                        thread::sleep(Duration::from_secs(60));
                    }
                }
            }
            return Ok(());
        }
        let allowed = available_cpus()?;
        let first_cpu = *allowed.first().context("no allowed CPU available")?;
        let tmp = tempfile::tempdir()?;
        let port_file = tmp.path().join("port'file");
        let wrapper = tmp.path().join("dummy'www.sh");
        let exe = std::env::current_exe()?;
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexport WWW_TEST_DUMMY_SERVER_PORT={}\nexec {} --exact tests::bench_server_drop_terminates_spawned_listener --nocapture -- \"$@\"\n",
                shell_single_quote(&port_file.display().to_string()),
                shell_single_quote(&exe.display().to_string()),
            ),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))?;
        }
        let log = tmp.path().join("server.log");
        let interrupted = AtomicBool::new(false);
        let (srv, url) = BenchServer::start(
            &wrapper,
            tmp.path(),
            CASES[0],
            "nodelay",
            &[first_cpu],
            log,
            &interrupted,
        )?;
        let host_port = url
            .strip_prefix("http://")
            .and_then(|s| s.split('/').next())
            .context("missing host:port in URL")?
            .to_owned();
        let addr: std::net::SocketAddr = host_port.parse()?;
        assert!(std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok());
        drop(srv);
        assert!(std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err());
        Ok(())
    }
}
