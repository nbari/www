//! Local HTTP/HTTPS benchmark runner.
//!
//! Two orthogonal axes are measured:
//!
//! * the server *implementation* (`rust`, the release binary built from the
//!   working tree, plus any external prebuilt binary registered with
//!   `--server LABEL=PATH`, e.g. the historical Go server),
//! * the TCP variant (`nodelay` vs `nagle`).
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

/// Label of the implicit implementation built from the working tree.
const RUST_LABEL: &str = "rust";
/// Label used for the historical Go implementation in ratio reporting.
const GO_LABEL: &str = "go";

/// Date far enough in the future that every fixture is "not modified since".
const FAR_FUTURE_DATE: &str = "Thu, 01 Jan 2099 00:00:00 GMT";
const CONDITIONAL_HEADERS: &[(&str, &str)] = &[("if-modified-since", FAR_FUTURE_DATE)];
const RANGE_HEADERS: &[(&str, &str)] = &[("range", "bytes=0-65535")];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Case {
    name: &'static str,
    path: &'static str,
    method: &'static str,
    headers: &'static [(&'static str, &'static str)],
    expected_status: u16,
    concurrency: usize,
    tls: bool,
    keepalive: bool,
}

impl Case {
    const fn get(name: &'static str, path: &'static str, concurrency: usize, tls: bool) -> Self {
        Self {
            name,
            path,
            method: "GET",
            headers: &[],
            expected_status: 200,
            concurrency,
            tls,
            keepalive: true,
        }
    }

    const fn head(mut self) -> Self {
        self.method = "HEAD";
        self
    }

    const fn conditional(mut self) -> Self {
        self.headers = CONDITIONAL_HEADERS;
        self.expected_status = 304;
        self
    }

    const fn ranged(mut self) -> Self {
        self.headers = RANGE_HEADERS;
        self.expected_status = 206;
        self
    }

    const fn no_keepalive(mut self) -> Self {
        self.keepalive = false;
        self
    }
}

const CASES: [Case; 26] = [
    Case::get("http-small-c1", "/small.bin", 1, false),
    Case::get("http-small-c16", "/small.bin", 16, false),
    Case::get("http-small-c64", "/small.bin", 64, false),
    Case::get("http-small-c128", "/small.bin", 128, false),
    Case::get("http-small-c16-noka", "/small.bin", 16, false).no_keepalive(),
    Case::get("http-medium-c16", "/medium.bin", 16, false),
    Case::get("http-medium-c64", "/medium.bin", 64, false),
    Case::get("http-large-c16", "/large.bin", 16, false),
    Case::get("http-listing-c16", "/listing/", 16, false),
    Case::get("http-listing-c64", "/listing/", 64, false),
    Case::get("http-head-c16", "/medium.bin", 16, false).head(),
    Case::get("http-conditional-c16", "/medium.bin", 16, false).conditional(),
    Case::get("http-range-c16", "/large.bin", 16, false).ranged(),
    Case::get("https-small-c1", "/small.bin", 1, true),
    Case::get("https-small-c16", "/small.bin", 16, true),
    Case::get("https-small-c64", "/small.bin", 64, true),
    Case::get("https-small-c128", "/small.bin", 128, true),
    Case::get("https-small-c16-noka", "/small.bin", 16, true).no_keepalive(),
    Case::get("https-medium-c16", "/medium.bin", 16, true),
    Case::get("https-medium-c64", "/medium.bin", 64, true),
    Case::get("https-large-c16", "/large.bin", 16, true),
    Case::get("https-listing-c16", "/listing/", 16, true),
    Case::get("https-listing-c64", "/listing/", 64, true),
    Case::get("https-head-c16", "/medium.bin", 16, true).head(),
    Case::get("https-conditional-c16", "/medium.bin", 16, true).conditional(),
    Case::get("https-range-c16", "/large.bin", 16, true).ranged(),
];

/// Length in bytes requested by a `Range: bytes=<start>-<end>` header.
fn range_header_length(headers: &[(&str, &str)]) -> Option<u64> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("range"))
        .map(|(_, value)| *value)?;
    let spec = value.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    Some(end - start + 1)
}

/// Body bytes a single response of `case` must carry, given the full size of
/// the requested resource.
fn expected_body_size(case: Case, resource_size: u64) -> u64 {
    if case.method == "HEAD" || case.expected_status == 304 {
        return 0;
    }
    if case.expected_status == 206 {
        return range_header_length(case.headers)
            .unwrap_or(resource_size)
            .min(resource_size);
    }
    resource_size
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProcIo {
    syscr: u64,
    syscw: u64,
    rchar: u64,
    wchar: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProcStatusCounters {
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
    threads: u64,
}

fn parse_labelled_u64(content: &str, key: &str) -> Result<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(key)
            && let Some(value) = rest.strip_prefix(':')
        {
            return value
                .split_whitespace()
                .next()
                .with_context(|| format!("missing value for {key}"))?
                .parse()
                .with_context(|| format!("invalid value for {key}"));
        }
    }
    bail!("missing {key} in /proc entry")
}

fn parse_proc_io(content: &str) -> Result<ProcIo> {
    Ok(ProcIo {
        syscr: parse_labelled_u64(content, "syscr")?,
        syscw: parse_labelled_u64(content, "syscw")?,
        rchar: parse_labelled_u64(content, "rchar")?,
        wchar: parse_labelled_u64(content, "wchar")?,
    })
}

fn parse_proc_status(content: &str) -> Result<ProcStatusCounters> {
    Ok(ProcStatusCounters {
        voluntary_ctxt_switches: parse_labelled_u64(content, "voluntary_ctxt_switches")?,
        nonvoluntary_ctxt_switches: parse_labelled_u64(content, "nonvoluntary_ctxt_switches")?,
        threads: parse_labelled_u64(content, "Threads")?,
    })
}

fn read_proc_io(pid: u32) -> Result<ProcIo> {
    let content = fs::read_to_string(format!("/proc/{pid}/io"))
        .with_context(|| format!("cannot read /proc/{pid}/io"))?;
    parse_proc_io(&content)
}

/// Context switches are per-task counters: `/proc/<pid>/status` reports only
/// the thread-group leader, which for a Tokio or Go server is almost idle.
/// Summing every thread under `/proc/<pid>/task` is what makes the figure a
/// server-wide count. `Threads` stays a process-level value.
fn read_proc_status(pid: u32) -> Result<ProcStatusCounters> {
    let content = fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("cannot read /proc/{pid}/status"))?;
    let mut counters = parse_proc_status(&content)?;
    let tasks = fs::read_dir(format!("/proc/{pid}/task"))
        .with_context(|| format!("cannot list /proc/{pid}/task"))?;
    let (mut voluntary, mut nonvoluntary) = (0_u64, 0_u64);
    for task in tasks {
        let path = task?.path().join("status");
        // A thread can exit between listing and reading; its counters are lost
        // either way, so a vanished thread is skipped rather than fatal.
        let Ok(thread) = fs::read_to_string(&path) else {
            continue;
        };
        let thread = parse_proc_status(&thread)?;
        voluntary = voluntary.saturating_add(thread.voluntary_ctxt_switches);
        nonvoluntary = nonvoluntary.saturating_add(thread.nonvoluntary_ctxt_switches);
    }
    counters.voluntary_ctxt_switches = voluntary;
    counters.nonvoluntary_ctxt_switches = nonvoluntary;
    Ok(counters)
}

/// Raw server-side counter deltas observed across one measured sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CounterDeltas {
    syscr: u64,
    syscw: u64,
    rchar: u64,
    wchar: u64,
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
}

impl CounterDeltas {
    fn between(
        io_before: ProcIo,
        io_after: ProcIo,
        status_before: ProcStatusCounters,
        status_after: ProcStatusCounters,
    ) -> Self {
        Self {
            syscr: io_after.syscr.saturating_sub(io_before.syscr),
            syscw: io_after.syscw.saturating_sub(io_before.syscw),
            rchar: io_after.rchar.saturating_sub(io_before.rchar),
            wchar: io_after.wchar.saturating_sub(io_before.wchar),
            voluntary_ctxt_switches: status_after
                .voluntary_ctxt_switches
                .saturating_sub(status_before.voluntary_ctxt_switches),
            nonvoluntary_ctxt_switches: status_after
                .nonvoluntary_ctxt_switches
                .saturating_sub(status_before.nonvoluntary_ctxt_switches),
        }
    }
}

/// Per-request derivations from the server-side counter deltas.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct PerRequestCounters {
    syscalls_read: f64,
    syscalls_write: f64,
    context_switches: f64,
    cpu_microseconds: f64,
}

#[allow(clippy::cast_precision_loss)]
fn per_request_counters(
    deltas: CounterDeltas,
    cpu_seconds: f64,
    requests: u64,
) -> PerRequestCounters {
    if requests == 0 {
        return PerRequestCounters::default();
    }
    let requests = requests as f64;
    PerRequestCounters {
        syscalls_read: (deltas.syscr as f64) / requests,
        syscalls_write: (deltas.syscw as f64) / requests,
        context_switches: ((deltas.voluntary_ctxt_switches + deltas.nonvoluntary_ctxt_switches)
            as f64)
            / requests,
        cpu_microseconds: cpu_seconds.max(0.0) * 1e6 / requests,
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SampleMetrics {
    case: String,
    implementation: String,
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
    cpu_microseconds_per_request: f64,
    sampled_peak_rss_mib: f64,
    client_wall_seconds: f64,
    deltas: CounterDeltas,
    syscalls_read_per_request: f64,
    syscalls_write_per_request: f64,
    context_switches_per_request: f64,
    server_threads: u64,
    raw_file: String,
    command: Vec<String>,
}

impl SampleMetrics {
    fn to_json(&self) -> Value {
        json!({
            "case": self.case,
            "implementation": self.implementation,
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
            "cpu_microseconds_per_request": self.cpu_microseconds_per_request,
            "sampled_peak_rss_mib": self.sampled_peak_rss_mib,
            "client_wall_seconds": self.client_wall_seconds,
            "syscr": self.deltas.syscr,
            "syscw": self.deltas.syscw,
            "rchar": self.deltas.rchar,
            "wchar": self.deltas.wchar,
            "voluntary_ctxt_switches": self.deltas.voluntary_ctxt_switches,
            "nonvoluntary_ctxt_switches": self.deltas.nonvoluntary_ctxt_switches,
            "syscalls_read_per_request": self.syscalls_read_per_request,
            "syscalls_write_per_request": self.syscalls_write_per_request,
            "context_switches_per_request": self.context_switches_per_request,
            "server_threads": self.server_threads,
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
    cpu_microseconds_per_request: f64,
    syscalls_read_per_request: f64,
    syscalls_write_per_request: f64,
    context_switches_per_request: f64,
    sampled_peak_rss_mib: f64,
    server_threads: u64,
    errors: u64,
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
            "cpu_microseconds_per_request": self.cpu_microseconds_per_request,
            "syscalls_read_per_request": self.syscalls_read_per_request,
            "syscalls_write_per_request": self.syscalls_write_per_request,
            "context_switches_per_request": self.context_switches_per_request,
            "sampled_peak_rss_mib": self.sampled_peak_rss_mib,
            "server_threads": self.server_threads,
            "errors": self.errors,
            "rps_range": self.rps_range,
            "rounds": self.rounds,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ImplementationSummary {
    variants: BTreeMap<String, VariantSummary>,
    nodelay_to_nagle_rps: Option<f64>,
}

impl ImplementationSummary {
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

#[derive(Clone, Debug, PartialEq)]
struct CaseSummary {
    implementations: BTreeMap<String, ImplementationSummary>,
    /// `rust` req/s divided by `go` req/s, keyed by TCP variant.
    rust_vs_go_rps: BTreeMap<String, f64>,
}

impl CaseSummary {
    fn to_json(&self) -> Value {
        let mut implementations = serde_json::Map::new();
        for (label, summary) in &self.implementations {
            implementations.insert(label.clone(), summary.to_json());
        }
        let mut map = serde_json::Map::new();
        map.insert("implementations".to_owned(), Value::Object(implementations));
        if !self.rust_vs_go_rps.is_empty() {
            let mut ratios = serde_json::Map::new();
            for (variant, ratio) in &self.rust_vs_go_rps {
                ratios.insert(variant.clone(), json!(ratio));
            }
            map.insert("rust_vs_go_rps".to_owned(), Value::Object(ratios));
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

fn median_u64(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or(0)
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

/// Split a `--server LABEL=PATH` specification.
fn parse_server_spec(spec: &str) -> Result<(String, String)> {
    let (label, path) = spec
        .split_once('=')
        .with_context(|| format!("--server expects LABEL=PATH, got {spec:?}"))?;
    let label = label.trim();
    let path = path.trim();
    if label.is_empty() || path.is_empty() {
        bail!("--server expects a non-empty LABEL and PATH, got {spec:?}");
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("--server label {label:?} must be alphanumeric with '-', '_' or '.'");
    }
    Ok((label.to_owned(), path.to_owned()))
}

/// All implementation labels in registration order, `rust` first.
fn registered_labels(specs: &[(String, String)]) -> Result<Vec<String>> {
    let mut labels = vec![RUST_LABEL.to_owned()];
    for (label, _) in specs {
        if label == RUST_LABEL {
            bail!("--server label {RUST_LABEL:?} is reserved for the working-tree release build");
        }
        if labels.iter().any(|known| known == label) {
            bail!("--server label {label:?} registered more than once");
        }
        labels.push(label.clone());
    }
    Ok(labels)
}

/// Resolve `--servers LIST` against the registered labels, preserving the
/// requested order. Without a selection every registered label runs.
fn select_implementation_labels(
    registered: &[String],
    selection: Option<&str>,
) -> Result<Vec<String>> {
    let Some(selection) = selection else {
        return Ok(registered.to_vec());
    };
    let mut selected: Vec<String> = Vec::new();
    for raw in selection.split(',') {
        let label = raw.trim();
        if label.is_empty() {
            continue;
        }
        if !registered.iter().any(|known| known == label) {
            bail!(
                "unknown implementation {label:?}; registered: {}",
                registered.join(", ")
            );
        }
        if selected.iter().any(|known| known == label) {
            bail!("implementation {label:?} selected more than once");
        }
        selected.push(label.to_owned());
    }
    if selected.is_empty() {
        bail!("--servers requires at least one registered implementation label");
    }
    Ok(selected)
}

#[allow(clippy::cast_precision_loss)]
fn validate_result(
    result: &Value,
    expected_size: u64,
    expected_status: u16,
) -> Result<SampleMetrics> {
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

    // `summary.total` is the elapsed wall time in seconds, never a request
    // count: request counts always come from `statusCodeDistribution`.
    let expected_key = expected_status.to_string();
    let count = statuses
        .get(&expected_key)
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let unexpected: u64 = statuses
        .iter()
        .filter(|(code, _)| *code != &expected_key)
        .filter_map(|(_, value)| value.as_u64())
        .sum();
    let errors = error_count.saturating_add(unexpected);
    if count == 0 {
        bail!(
            "no HTTP {expected_status} responses: statuses={statuses:?}, errors={errors_obj:?}, successRate={success_rate}"
        );
    }

    let total_data = summary
        .get("totalData")
        .and_then(Value::as_u64)
        .context("oha summary missing integer totalData")?;
    if errors == 0 && total_data != count.saturating_mul(expected_size) {
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
        implementation: String::new(),
        variant: String::new(),
        round: 0,
        requests: count,
        errors,
        seconds: total_secs,
        rps: (count as f64) / total_secs,
        mib_per_second: (total_data as f64) / total_secs / (1024.0 * 1024.0),
        p50_ms: p50 * 1000.0,
        p95_ms: p95 * 1000.0,
        p99_ms: p99 * 1000.0,
        response_bytes: expected_size,
        server_cpu_cores: 0.0,
        cpu_microseconds_per_request: 0.0,
        sampled_peak_rss_mib: 0.0,
        client_wall_seconds: 0.0,
        deltas: CounterDeltas::default(),
        syscalls_read_per_request: 0.0,
        syscalls_write_per_request: 0.0,
        context_switches_per_request: 0.0,
        server_threads: 0,
        raw_file: String::new(),
        command: Vec::new(),
    })
}

fn summarize_variant(rows: &[&SampleMetrics]) -> VariantSummary {
    let rps_vals: Vec<f64> = rows.iter().map(|r| r.rps).collect();
    let min_rps = rps_vals.iter().copied().fold(f64::INFINITY, f64::min);
    let max_rps = rps_vals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    VariantSummary {
        rps: median(rps_vals),
        mib_per_second: median(rows.iter().map(|r| r.mib_per_second).collect()),
        p50_ms: median(rows.iter().map(|r| r.p50_ms).collect()),
        p95_ms: median(rows.iter().map(|r| r.p95_ms).collect()),
        p99_ms: median(rows.iter().map(|r| r.p99_ms).collect()),
        server_cpu_cores: median(rows.iter().map(|r| r.server_cpu_cores).collect()),
        cpu_microseconds_per_request: median(
            rows.iter()
                .map(|r| r.cpu_microseconds_per_request)
                .collect(),
        ),
        syscalls_read_per_request: median(
            rows.iter().map(|r| r.syscalls_read_per_request).collect(),
        ),
        syscalls_write_per_request: median(
            rows.iter().map(|r| r.syscalls_write_per_request).collect(),
        ),
        context_switches_per_request: median(
            rows.iter()
                .map(|r| r.context_switches_per_request)
                .collect(),
        ),
        sampled_peak_rss_mib: median(rows.iter().map(|r| r.sampled_peak_rss_mib).collect()),
        server_threads: median_u64(rows.iter().map(|r| r.server_threads).collect()),
        errors: rows.iter().map(|r| r.errors).sum(),
        rps_range: [min_rps, max_rps],
        rounds: rows.len(),
    }
}

/// Group samples by case, then implementation, then variant. Nothing is ever
/// averaged across cases or across implementations.
fn aggregate(samples: &[SampleMetrics]) -> BTreeMap<String, CaseSummary> {
    type Grouped<'a> = BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<&'a SampleMetrics>>>>;
    let mut grouped: Grouped<'_> = BTreeMap::new();
    for sample in samples {
        // A sample with unexpected statuses or transport errors has already
        // had its payload-size validation skipped, and its throughput and
        // latency populations no longer match its request count. It stays in
        // report.json as raw evidence but must never enter a published median
        // or ratio.
        if sample.errors > 0 {
            continue;
        }
        grouped
            .entry(sample.case.clone())
            .or_default()
            .entry(sample.implementation.clone())
            .or_default()
            .entry(sample.variant.clone())
            .or_default()
            .push(sample);
    }
    let mut summary = BTreeMap::new();
    for (name, implementations) in grouped {
        if implementations.is_empty() {
            continue;
        }
        let round_counts: BTreeSet<usize> = implementations
            .values()
            .flat_map(|variants| variants.values().map(Vec::len))
            .collect();
        if round_counts.len() != 1 {
            continue;
        }
        let mut case_implementations = BTreeMap::new();
        for (implementation, variants) in implementations {
            let mut case_variants = BTreeMap::new();
            for (variant, rows) in variants {
                case_variants.insert(variant, summarize_variant(&rows));
            }
            let nodelay_to_nagle_rps =
                match (case_variants.get("nodelay"), case_variants.get("nagle")) {
                    (Some(nd), Some(ng)) if ng.rps > 0.0 => Some(nd.rps / ng.rps),
                    _ => None,
                };
            case_implementations.insert(
                implementation,
                ImplementationSummary {
                    variants: case_variants,
                    nodelay_to_nagle_rps,
                },
            );
        }
        let mut rust_vs_go_rps = BTreeMap::new();
        if let (Some(rust), Some(go)) = (
            case_implementations.get(RUST_LABEL),
            case_implementations.get(GO_LABEL),
        ) {
            for (variant, rust_summary) in &rust.variants {
                if let Some(go_summary) = go.variants.get(variant)
                    && go_summary.rps > 0.0
                {
                    rust_vs_go_rps.insert(variant.clone(), rust_summary.rps / go_summary.rps);
                }
            }
        }
        summary.insert(
            name,
            CaseSummary {
                implementations: case_implementations,
                rust_vs_go_rps,
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

/// SMT siblings of `cpu`, read from the kernel topology. An unreadable or
/// absent topology (containers, non-SMT machines) yields just `cpu` itself.
fn thread_siblings(cpu: usize) -> Vec<usize> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    fs::read_to_string(path)
        .ok()
        .and_then(|list| parse_cpu_list(&list).ok())
        .unwrap_or_else(|| vec![cpu])
}

/// Split the allowed CPUs into a server set and a load-generator set that
/// share no PHYSICAL core.
///
/// Splitting by logical index alone silently hands the client the SMT siblings
/// of the server's cores, so the two processes compete for the same execution
/// units and every measured server cost is inflated. Sibling exclusion is what
/// makes the server and client budgets independent.
fn split_cpus(cpus: &[usize], server_cpu_count: usize) -> Result<(Vec<usize>, Vec<usize>)> {
    let server: Vec<usize> = cpus.iter().copied().take(server_cpu_count).collect();
    if server.len() < server_cpu_count {
        bail!("not enough allowed CPUs for {server_cpu_count} server CPUs");
    }
    let reserved: BTreeSet<usize> = server
        .iter()
        .flat_map(|cpu| thread_siblings(*cpu))
        .chain(server.iter().copied())
        .collect();
    let client: Vec<usize> = cpus
        .iter()
        .copied()
        .filter(|cpu| !reserved.contains(cpu))
        .collect();
    if client.is_empty() {
        bail!(
            "no CPUs left for the load generator after reserving the server cores and their SMT siblings ({reserved:?})"
        );
    }
    Ok((server, client))
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

/// Preflight one case against a running server and return the body size every
/// load-generated response must carry.
#[allow(clippy::cast_precision_loss)]
async fn verify_endpoint(url: &str, fixtures: &Path, case: Case) -> Result<u64> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(case.tls)
        .timeout(Duration::from_secs(10))
        .build()?;
    let method = reqwest::Method::from_bytes(case.method.as_bytes())
        .with_context(|| format!("invalid HTTP method {}", case.method))?;
    let mut request = client
        .request(method, url)
        .header("accept-encoding", "identity");
    for (name, value) in case.headers {
        request = request.header(*name, *value);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("preflight {} failed for {url}", case.method))?;
    let status = response.status().as_u16();
    if status != case.expected_status {
        bail!(
            "preflight {} {url} returned HTTP {status}, expected {}",
            case.method,
            case.expected_status
        );
    }
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let body = response.bytes().await?;
    let body_len = body.len() as u64;

    let is_listing = case.path == "/listing/";
    let resource_size = if is_listing {
        body_len
    } else {
        let relative = case.path.trim_start_matches('/');
        fs::metadata(fixtures.join(relative))?.len()
    };
    let expected = expected_body_size(case, resource_size);

    if case.method == "HEAD" {
        if body_len != 0 {
            bail!("HEAD response carried {body_len} body bytes");
        }
        match content_length {
            Some(len) if len == resource_size => {}
            other => {
                bail!("HEAD Content-Length {other:?} differs from fixture size {resource_size}")
            }
        }
        return Ok(expected);
    }
    if case.expected_status == 304 {
        if body_len != 0 {
            bail!("304 response carried {body_len} body bytes");
        }
        return Ok(expected);
    }
    if body_len != expected {
        bail!(
            "preflight body is {body_len} bytes, expected {expected} for {}",
            case.name
        );
    }
    if is_listing {
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
        let fixture = fs::read(fixtures.join(relative))?;
        let reference = fixture
            .get(..usize::try_from(expected)?)
            .context("range exceeds fixture size")?;
        if body.as_ref() != reference {
            bail!("preflight response bytes differ from fixture {}", case.path);
        }
    }
    Ok(expected)
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
            .env("GOMAXPROCS", cpus.len().to_string())
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
            "-m".to_owned(),
            self.case.method.to_owned(),
        ];
        for (name, value) in self.case.headers {
            args.push("-H".to_owned());
            args.push(format!("{name}: {value}"));
        }
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

/// Append `suffix` to the WHOLE prefix filename.
///
/// `Path::with_extension` REPLACES everything after the last dot, so a label
/// containing a dot (`--server go.v1=...`) would make every round, phase and
/// variant write to the same file and silently destroy the raw evidence.
fn artifact_path(prefix: &Path, suffix: &str) -> PathBuf {
    let mut name = prefix.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    prefix.with_file_name(name)
}

#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
fn run_oha_sample(run: &OhaRun<'_>, server: &mut BenchServer) -> Result<SampleMetrics> {
    if run.interrupted.load(Ordering::SeqCst) {
        return Err(InterruptedError.into());
    }
    let full = pinned_command(run.cpus, run.oha, &run.args());
    let raw_path = artifact_path(run.prefix, "json");
    let err_path = artifact_path(run.prefix, "stderr");
    let out_file = fs::File::create(&raw_path)?;
    let err_file = fs::File::create(&err_path)?;

    let pid = server.child.id();
    let (cpu_before, mut peak_rss) = process_usage(pid, run.sys)?;
    let io_before = read_proc_io(pid)?;
    let status_before = read_proc_status(pid)?;
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
        if let Ok((_, rss)) = process_usage(pid, run.sys) {
            peak_rss = peak_rss.max(rss);
        }
        thread::sleep(Duration::from_millis(25));
    }

    let elapsed = started.elapsed().as_secs_f64();
    let (cpu_after, rss_after) = process_usage(pid, run.sys)?;
    let io_after = read_proc_io(pid)?;
    let status_after = read_proc_status(pid)?;
    if server.child.try_wait()?.is_some() {
        bail!("server exited during load test completion");
    }
    peak_rss = peak_rss.max(rss_after);
    let raw_json: Value = serde_json::from_str(&fs::read_to_string(&raw_path)?)
        .with_context(|| format!("invalid JSON in {}", raw_path.display()))?;
    let mut metrics = validate_result(&raw_json, run.expected_size, run.case.expected_status)?;
    let cpu_seconds = (cpu_after - cpu_before).max(0.0);
    let deltas = CounterDeltas::between(io_before, io_after, status_before, status_after);
    let per_request = per_request_counters(deltas, cpu_seconds, metrics.requests);
    metrics.server_cpu_cores = cpu_seconds / elapsed;
    metrics.cpu_microseconds_per_request = per_request.cpu_microseconds;
    metrics.syscalls_read_per_request = per_request.syscalls_read;
    metrics.syscalls_write_per_request = per_request.syscalls_write;
    metrics.context_switches_per_request = per_request.context_switches;
    metrics.deltas = deltas;
    metrics.server_threads = status_after.threads;
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

/// One server binary under test.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Implementation {
    label: String,
    path: PathBuf,
    bytes: u64,
    sha256: String,
    /// `true` only for the implicit working-tree release build.
    rust_build: bool,
}

impl Implementation {
    fn to_json(&self) -> Value {
        json!({
            "label": self.label,
            "path": self.path.display().to_string(),
            "bytes": self.bytes,
            "sha256": self.sha256,
            "source": if self.rust_build { "working-tree release build" } else { "external prebuilt binary" },
        })
    }
}

fn summary_rows(summary: &BTreeMap<String, CaseSummary>) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<24} {:<10} {:<8} {:>11} {:>10} {:>9} {:>9} {:>9} {:>11} {:>10} {:>10} {:>9} {:>9} {:>5} {:>7} {:>9}",
        "Case",
        "Impl",
        "Variant",
        "req/s",
        "MiB/s",
        "p50 ms",
        "p95 ms",
        "p99 ms",
        "cpu us/req",
        "rd sc/req",
        "wr sc/req",
        "ctx/req",
        "RSS MiB",
        "thr",
        "errors",
        "rust/go",
    ));
    for (name, case_sum) in summary {
        for (label, impl_sum) in &case_sum.implementations {
            for (variant, m) in &impl_sum.variants {
                let ratio = if label == RUST_LABEL {
                    case_sum
                        .rust_vs_go_rps
                        .get(variant)
                        .map_or_else(|| "-".to_owned(), |r| format!("{r:.3}x"))
                } else {
                    "-".to_owned()
                };
                lines.push(format!(
                    "{name:<24} {label:<10} {variant:<8} {:>11.0} {:>10.2} {:>9.3} {:>9.3} {:>9.3} {:>11.1} {:>10.3} {:>10.3} {:>9.3} {:>9.1} {:>5} {:>7} {ratio:>9}",
                    m.rps,
                    m.mib_per_second,
                    m.p50_ms,
                    m.p95_ms,
                    m.p99_ms,
                    m.cpu_microseconds_per_request,
                    m.syscalls_read_per_request,
                    m.syscalls_write_per_request,
                    m.context_switches_per_request,
                    m.sampled_peak_rss_mib,
                    m.server_threads,
                    m.errors,
                ));
            }
        }
    }
    let mut nagle_lines = Vec::new();
    for (name, case_sum) in summary {
        for (label, impl_sum) in &case_sum.implementations {
            if let Some(ratio) = impl_sum.nodelay_to_nagle_rps {
                nagle_lines.push(format!("{name:<24} {label:<10} {ratio:>8.3}x"));
            }
        }
    }
    if !nagle_lines.is_empty() {
        lines.push(String::new());
        lines.push("nodelay / nagle req/s ratio".to_owned());
        lines.push(format!("{:<24} {:<10} {:>9}", "Case", "Impl", "Speedup"));
        lines.extend(nagle_lines);
    }
    lines
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
        "case,implementation,variant,round,requests,errors,rps,mib_per_second,p50_ms,p95_ms,p99_ms,server_cpu_cores,cpu_microseconds_per_request,syscalls_read_per_request,syscalls_write_per_request,context_switches_per_request,sampled_peak_rss_mib,server_threads\n",
    );
    for s in samples {
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{}",
            s.case,
            s.implementation,
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
            s.cpu_microseconds_per_request,
            s.syscalls_read_per_request,
            s.syscalls_write_per_request,
            s.context_switches_per_request,
            s.sampled_peak_rss_mib,
            s.server_threads,
        );
    }
    fs::write(output_dir.join("samples.csv"), csv)?;

    let implementations = metadata
        .get("selected_implementations")
        .and_then(Value::as_array)
        .map(|labels| {
            labels
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let mut lines = vec![
        format!("Status: {status}"),
        format!("Implementations: {implementations}"),
        "Medians across rounds, per case and implementation; nothing is averaged across cases or implementations."
            .to_owned(),
        String::new(),
    ];
    lines.extend(summary_rows(&summary));
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
    servers: Vec<(String, String)>,
    server_selection: Option<String>,
    output: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
fn parse_args() -> Result<CliArgs> {
    let mut oha = std::env::var("WWW_BENCH_OHA").unwrap_or_else(|_| "oha".to_owned());
    let mut mode = String::from("all");
    let mut variants = String::from("both");
    let mut duration = 2.0_f64;
    let mut warmup = 0.5_f64;
    let mut repeats = 3_usize;
    let mut server_cpus = None;
    let mut cases = Vec::new();
    let mut servers = Vec::new();
    let mut server_selection = None;
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
            "--server" => {
                let spec = iter.next().context("--server requires LABEL=PATH")?;
                servers.push(parse_server_spec(&spec)?);
            }
            "--servers" => {
                server_selection = Some(
                    iter.next()
                        .context("--servers requires a comma separated label list")?,
                );
            }
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
    // Fail fast on bad labels before anything is built.
    let registered = registered_labels(&servers)?;
    select_implementation_labels(&registered, server_selection.as_deref())?;
    Ok(CliArgs {
        oha,
        mode,
        variants,
        duration,
        warmup,
        repeats,
        server_cpus,
        cases,
        servers,
        server_selection,
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

/// Build the working-tree binary and resolve every external server, returning
/// the implementations in the selected execution order.
fn resolve_implementations(args: &CliArgs, output_dir: &Path) -> Result<Vec<Implementation>> {
    println!("Building optimized release binary (details in build.log)...");
    let binary = build_release_binary(output_dir)?;
    let (bin_bytes, bin_sha256) = sha256_file(&binary)?;
    let mut registered = vec![Implementation {
        label: RUST_LABEL.to_owned(),
        path: binary,
        bytes: bin_bytes,
        sha256: bin_sha256,
        rust_build: true,
    }];
    for (label, path) in &args.servers {
        let resolved = PathBuf::from(resolve_executable(path).with_context(|| {
            format!("--server {label}={path} does not point at an executable file")
        })?);
        let (bytes, sha256) = sha256_file(&resolved)?;
        registered.push(Implementation {
            label: label.clone(),
            path: resolved,
            bytes,
            sha256,
            rust_build: false,
        });
    }
    let labels: Vec<String> = registered.iter().map(|i| i.label.clone()).collect();
    let selected = select_implementation_labels(&labels, args.server_selection.as_deref())?;
    let mut ordered = Vec::with_capacity(selected.len());
    for label in selected {
        let found = registered
            .iter()
            .find(|i| i.label == label)
            .with_context(|| format!("implementation {label} disappeared"))?;
        ordered.push(found.clone());
    }
    Ok(ordered)
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
    let implementations = resolve_implementations(&args, &output_dir)?;

    let (server_cpus, client_cpus) = split_cpus(&cpus, server_cpu_count)?;
    let (server_cpus, client_cpus) = (server_cpus.as_slice(), client_cpus.as_slice());
    let mut metadata = build_metadata(
        &args,
        sys,
        &oha_version,
        &active_variants,
        server_cpus,
        client_cpus,
        &implementations,
    )?;

    let mut samples = Vec::new();
    save_report("running", &metadata, &samples, &output_dir)?;
    let interrupted = install_signal_watcher()?;

    let run_result = execute_matrix(
        &args,
        sys,
        &interrupted,
        &oha,
        &implementations,
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
    implementations: &[Implementation],
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
    let rust_commit = capture("git", &["rev-parse", "HEAD"])?;
    let worktree_status = capture("git", &["status", "--porcelain"])?;
    let build_flags = ["--release", "--locked", "--bin", "www"];
    let mut metadata = serde_json::Map::new();
    metadata.insert("cpu_model".to_owned(), json!(cpu_model));
    metadata.insert("server_cpus".to_owned(), json!(server_cpus));
    metadata.insert("client_cpus".to_owned(), json!(client_cpus));
    metadata.insert(
        "clock_ticks_per_second".to_owned(),
        json!(sys.ticks_per_sec),
    );
    metadata.insert("page_size_bytes".to_owned(), json!(sys.page_size));
    metadata.insert("rust_commit".to_owned(), json!(rust_commit));
    metadata.insert("rust_worktree_status".to_owned(), json!(worktree_status));
    metadata.insert(
        "rust_version".to_owned(),
        json!(capture("rustc", &["--version"])?),
    );
    metadata.insert(
        "cargo_version".to_owned(),
        json!(capture("cargo", &["--version"])?),
    );
    metadata.insert("oha_version".to_owned(), json!(oha_version));
    metadata.insert("rust_build_flags".to_owned(), json!(build_flags));
    let entries: Vec<Value> = implementations
        .iter()
        .map(|implementation| {
            let mut value = implementation.to_json();
            if implementation.rust_build
                && let Some(object) = value.as_object_mut()
            {
                object.insert("build_flags".to_owned(), json!(build_flags));
                object.insert("commit".to_owned(), json!(rust_commit));
                object.insert("worktree_status".to_owned(), json!(worktree_status));
            }
            value
        })
        .collect();
    if let Some(rust) = implementations.iter().find(|i| i.rust_build) {
        metadata.insert(
            "build".to_owned(),
            json!({ "bytes": rust.bytes, "sha256": rust.sha256 }),
        );
    }
    metadata.insert("implementations".to_owned(), Value::Array(entries));
    metadata.insert(
        "selected_implementations".to_owned(),
        json!(
            implementations
                .iter()
                .map(|i| i.label.clone())
                .collect::<Vec<_>>()
        ),
    );
    metadata.insert("mode".to_owned(), json!(args.mode));
    metadata.insert("variants".to_owned(), json!(active_variants));
    metadata.insert("duration_seconds".to_owned(), json!(args.duration));
    metadata.insert("warmup_seconds".to_owned(), json!(args.warmup));
    metadata.insert("repeats".to_owned(), json!(args.repeats));
    Ok(metadata)
}

/// Rotate `items` by one position on odd rotations so neither implementation
/// nor variant order can bias the medians.
fn alternate<T: Clone>(items: &[T], rotate: bool) -> Vec<T> {
    let mut order = items.to_vec();
    if rotate && order.len() > 1 {
        order.reverse();
    }
    order
}

struct SampleContext<'a> {
    implementation: &'a Implementation,
    case: Case,
    variant: &'a str,
    round: usize,
}

#[allow(clippy::too_many_arguments)]
async fn run_single_sample(
    args: &CliArgs,
    sys: SystemMetricsConfig,
    interrupted: &AtomicBool,
    oha: &str,
    fixtures: &Path,
    server_cpus: &[usize],
    client_cpus: &[usize],
    output_dir: &Path,
    ctx: &SampleContext<'_>,
) -> Result<SampleMetrics> {
    let SampleContext {
        implementation,
        case,
        variant,
        round,
    } = *ctx;
    let stem = format!("{}-{}-{round}-{variant}", case.name, implementation.label);
    let prefix = output_dir.join(&stem);
    let (mut srv, url) = BenchServer::start(
        &implementation.path,
        fixtures,
        case,
        variant,
        server_cpus,
        artifact_path(&prefix, "server.log"),
        interrupted,
    )?;
    let expected = verify_endpoint(&url, fixtures, case)
        .await
        .with_context(|| {
            format!(
                "preflight failed for {} on {}",
                case.name, implementation.label
            )
        })?;
    run_oha_sample(
        &OhaRun {
            oha,
            url: &url,
            case,
            duration: 1.0,
            cpus: client_cpus,
            prefix: &output_dir.join(format!("{stem}-preflight")),
            expected_size: expected,
            count: Some(1),
            sys,
            interrupted,
        },
        &mut srv,
    )?;
    run_oha_sample(
        &OhaRun {
            oha,
            url: &url,
            case,
            duration: args.warmup,
            cpus: client_cpus,
            prefix: &output_dir.join(format!("{stem}-warmup")),
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
    implementation.label.clone_into(&mut metrics.implementation);
    variant.clone_into(&mut metrics.variant);
    metrics.round = round;
    Ok(metrics)
}

#[allow(clippy::too_many_arguments)]
async fn execute_matrix(
    args: &CliArgs,
    sys: SystemMetricsConfig,
    interrupted: &AtomicBool,
    oha: &str,
    implementations: &[Implementation],
    selected_cases: &[Case],
    active_variants: &[&str],
    server_cpus: &[usize],
    client_cpus: &[usize],
    output_dir: &Path,
    metadata: &serde_json::Map<String, Value>,
    samples: &mut Vec<SampleMetrics>,
) -> Result<()> {
    // The Nagle variant exists only for this server's TCP_NODELAY toggle, so a
    // selection of external implementations with only that variant schedules
    // nothing. Failing here beats writing a "complete" report with no rows.
    if !implementations
        .iter()
        .any(|implementation| implementation.label == RUST_LABEL)
        && active_variants == ["nagle"]
    {
        bail!(
            "the nagle variant applies only to the `{RUST_LABEL}` implementation; this selection schedules no samples"
        );
    }
    let fixtures = tempfile::tempdir()?;
    fixture_tree(fixtures.path())?;
    for repeat in 0..args.repeats {
        for (index, &case) in selected_cases.iter().enumerate() {
            let impl_order = alternate(implementations, (repeat + index) % 2 == 1);
            for (impl_index, implementation) in impl_order.iter().enumerate() {
                let variant_order =
                    alternate(active_variants, (repeat + index + impl_index) % 2 == 1);
                for variant in variant_order {
                    // `WWW_BENCH_DISABLE_TCP_NODELAY` is read by this server
                    // only. An external binary (the historical Go server sets
                    // TCP_NODELAY unconditionally) would run an identical
                    // configuration under both labels, so recording it as a
                    // second variant would invent a comparison that does not
                    // exist.
                    if variant == "nagle" && implementation.label != RUST_LABEL {
                        continue;
                    }
                    if interrupted.load(Ordering::SeqCst) {
                        return Err(InterruptedError.into());
                    }
                    println!(
                        "[{}/{}] {}: {} {variant}",
                        repeat + 1,
                        args.repeats,
                        case.name,
                        implementation.label
                    );
                    let metrics = run_single_sample(
                        args,
                        sys,
                        interrupted,
                        oha,
                        fixtures.path(),
                        server_cpus,
                        client_cpus,
                        output_dir,
                        &SampleContext {
                            implementation,
                            case,
                            variant,
                            round: repeat + 1,
                        },
                    )
                    .await?;
                    if metrics.errors > 0 {
                        println!(
                            "  warning: {} unexpected responses from {} ({})",
                            metrics.errors, implementation.label, case.name
                        );
                    }
                    samples.push(metrics);
                    save_report("running", metadata, samples, output_dir)?;
                }
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

    fn sample(case: &str, implementation: &str, variant: &str, val: f64) -> SampleMetrics {
        SampleMetrics {
            case: case.to_owned(),
            implementation: implementation.to_owned(),
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
            cpu_microseconds_per_request: val,
            sampled_peak_rss_mib: val,
            client_wall_seconds: 1.0,
            deltas: CounterDeltas::default(),
            syscalls_read_per_request: val,
            syscalls_write_per_request: val,
            context_switches_per_request: val,
            server_threads: 4,
            raw_file: String::new(),
            command: Vec::new(),
        }
    }

    #[test]
    fn validate_result_preserves_units_and_rejects_errors_or_bad_bodies() -> Result<()> {
        let metrics = validate_result(&valid_oha_json(), 1024, 200)?;
        assert!((metrics.rps - 5.0).abs() < f64::EPSILON);
        assert!((metrics.p50_ms - 1.0).abs() < f64::EPSILON);
        assert!((metrics.p95_ms - 2.0).abs() < f64::EPSILON);
        assert!((metrics.p99_ms - 3.0).abs() < f64::EPSILON);
        assert!((metrics.mib_per_second - 5.0 / 1024.0).abs() < f64::EPSILON);
        // `summary.total` is seconds, never a request count.
        assert_eq!(metrics.requests, 10);
        assert!((metrics.seconds - 2.0).abs() < f64::EPSILON);
        assert_eq!(metrics.errors, 0);

        let mut http_err = valid_oha_json();
        http_err["statusCodeDistribution"] = json!({"404": 10});
        assert!(validate_result(&http_err, 1024, 200).is_err());

        let mut body_err = valid_oha_json();
        body_err["summary"]["totalData"] = json!(10239);
        assert!(validate_result(&body_err, 1024, 200).is_err());

        let mut aborted = valid_oha_json();
        aborted["errorDistribution"] = json!({"aborted due to deadline": 1});
        let aborted_metrics = validate_result(&aborted, 1024, 200)?;
        assert_eq!(aborted_metrics.errors, 1);

        let mut zero_time = valid_oha_json();
        zero_time["summary"]["total"] = json!(0.0);
        assert!(validate_result(&zero_time, 1024, 200).is_err());
        Ok(())
    }

    #[test]
    fn validate_result_honours_per_case_status_and_size() -> Result<()> {
        let mut ranged = valid_oha_json();
        ranged["statusCodeDistribution"] = json!({"206": 4});
        ranged["summary"]["totalData"] = json!(4 * 65536);
        let metrics = validate_result(&ranged, 65536, 206)?;
        assert_eq!(metrics.requests, 4);
        assert_eq!(metrics.errors, 0);
        // The same payload is rejected when 200 was expected.
        assert!(validate_result(&ranged, 65536, 200).is_err());

        let mut not_modified = valid_oha_json();
        not_modified["statusCodeDistribution"] = json!({"304": 7});
        not_modified["summary"]["totalData"] = json!(0);
        let metrics = validate_result(&not_modified, 0, 304)?;
        assert_eq!(metrics.requests, 7);

        // Mixed statuses are counted as errors, not silently accepted.
        let mut mixed = valid_oha_json();
        mixed["statusCodeDistribution"] = json!({"200": 8, "500": 2});
        let metrics = validate_result(&mixed, 1024, 200)?;
        assert_eq!(metrics.requests, 8);
        assert_eq!(metrics.errors, 2);
        Ok(())
    }

    #[test]
    fn expected_body_sizes_cover_head_conditional_and_range() {
        let head = CASES
            .iter()
            .find(|c| c.name == "http-head-c16")
            .copied()
            .map(|c| expected_body_size(c, 100 * 1024));
        assert_eq!(head, Some(0));
        let conditional = CASES
            .iter()
            .find(|c| c.name == "http-conditional-c16")
            .copied()
            .map(|c| expected_body_size(c, 100 * 1024));
        assert_eq!(conditional, Some(0));
        let ranged = CASES
            .iter()
            .find(|c| c.name == "http-range-c16")
            .copied()
            .map(|c| expected_body_size(c, 4 * 1024 * 1024));
        assert_eq!(ranged, Some(65536));
        let plain = CASES
            .iter()
            .find(|c| c.name == "http-medium-c16")
            .copied()
            .map(|c| expected_body_size(c, 100 * 1024));
        assert_eq!(plain, Some(100 * 1024));
        assert_eq!(range_header_length(RANGE_HEADERS), Some(65536));
        assert_eq!(range_header_length(&[("range", "bytes=5-1")]), None);
        assert_eq!(range_header_length(&[]), None);
    }

    #[test]
    fn oha_arguments_carry_method_headers_and_keepalive() {
        let interrupted = AtomicBool::new(false);
        let sys = SystemMetricsConfig {
            ticks_per_sec: 100.0,
            page_size: 4096,
        };
        let cpus = [0_usize];
        let prefix = PathBuf::from("/tmp/prefix");
        let case = CASES
            .iter()
            .find(|c| c.name == "http-range-c16")
            .copied()
            .unwrap_or(CASES[0]);
        let run = OhaRun {
            oha: "oha",
            url: "http://127.0.0.1:1/large.bin",
            case,
            duration: 1.0,
            cpus: &cpus,
            prefix: &prefix,
            expected_size: 65536,
            count: None,
            sys,
            interrupted: &interrupted,
        };
        let args = run.args();
        let method_at = args.iter().position(|a| a == "-m");
        assert_eq!(
            method_at.and_then(|i| args.get(i + 1)).map(String::as_str),
            Some("GET")
        );
        assert!(args.iter().any(|a| a == "range: bytes=0-65535"));
        assert!(!args.iter().any(|a| a == "--disable-keepalive"));

        let no_ka = CASES
            .iter()
            .find(|c| c.name == "http-small-c16-noka")
            .copied()
            .unwrap_or(CASES[0]);
        let run = OhaRun { case: no_ka, ..run };
        assert!(run.args().iter().any(|a| a == "--disable-keepalive"));

        let head = CASES
            .iter()
            .find(|c| c.name == "https-head-c16")
            .copied()
            .unwrap_or(CASES[0]);
        let run = OhaRun { case: head, ..run };
        let args = run.args();
        let method_at = args.iter().position(|a| a == "-m");
        assert_eq!(
            method_at.and_then(|i| args.get(i + 1)).map(String::as_str),
            Some("HEAD")
        );
        assert!(args.iter().any(|a| a == "--insecure"));
    }

    #[test]
    fn aggregate_uses_medians_and_rejects_unequal_rounds() {
        let make = |variant: &str, val: f64| sample("http-small-c1", RUST_LABEL, variant, val);
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
            let rust = case.implementations.get(RUST_LABEL);
            assert!(rust.is_some_and(|r| r.nodelay_to_nagle_rps == Some(2.0)));
            let nagle = rust.and_then(|r| r.variants.get("nagle"));
            assert!(nagle.is_some_and(|n| n.rps_range == [10.0, 100.0] && n.rounds == 3));
        }

        let unequal = vec![
            make("nodelay", 10.0),
            make("nagle", 20.0),
            make("nodelay", 30.0),
        ];
        assert!(aggregate(&unequal).is_empty());
    }

    /// A dotted implementation label must not collapse every round, phase and
    /// variant onto one raw-evidence file.
    #[test]
    fn artifact_paths_stay_unique_for_dotted_labels() {
        let dir = Path::new("/tmp/bench");
        let round_one = artifact_path(&dir.join("http-small-c16-go.v1-1-nodelay"), "json");
        let round_two = artifact_path(&dir.join("http-small-c16-go.v1-2-nodelay"), "json");
        let log = artifact_path(&dir.join("http-small-c16-go.v1-1-nodelay"), "server.log");
        assert_ne!(round_one, round_two);
        assert_ne!(round_one, log);
        assert_eq!(
            round_one,
            dir.join("http-small-c16-go.v1-1-nodelay.json"),
            "the whole filename must be preserved"
        );
    }

    /// Samples whose payload validation was skipped must stay out of medians.
    #[test]
    fn aggregate_excludes_samples_with_errors() {
        let mut clean = sample("http-small-c16", RUST_LABEL, "nodelay", 200.0);
        clean.errors = 0;
        let mut failed = sample("http-small-c16", GO_LABEL, "nodelay", 100.0);
        failed.errors = 7;
        let summary = aggregate(&[clean, failed]);
        let case = summary.get("http-small-c16");
        assert!(case.is_some_and(|c| c.implementations.contains_key(RUST_LABEL)));
        assert!(
            case.is_some_and(|c| !c.implementations.contains_key(GO_LABEL)),
            "a sample with errors must not produce a published median"
        );
    }

    #[test]
    fn aggregate_keeps_implementations_separate_and_reports_rust_vs_go() {
        let samples = vec![
            sample("http-small-c16", RUST_LABEL, "nodelay", 200.0),
            sample("http-small-c16", GO_LABEL, "nodelay", 100.0),
            sample("http-large-c16", RUST_LABEL, "nodelay", 50.0),
            sample("http-large-c16", GO_LABEL, "nodelay", 25.0),
        ];
        let summary = aggregate(&samples);
        assert_eq!(summary.len(), 2);
        let small = summary.get("http-small-c16");
        assert!(small.is_some());
        if let Some(small) = small {
            assert_eq!(small.implementations.len(), 2);
            assert_eq!(small.rust_vs_go_rps.get("nodelay"), Some(&2.0));
            let rust_rps = small
                .implementations
                .get(RUST_LABEL)
                .and_then(|i| i.variants.get("nodelay"))
                .map(|v| v.rps);
            assert_eq!(rust_rps, Some(200.0));
            let go_rps = small
                .implementations
                .get(GO_LABEL)
                .and_then(|i| i.variants.get("nodelay"))
                .map(|v| v.rps);
            assert_eq!(go_rps, Some(100.0));
        }
        // Without a go run there is no ratio and no cross-case averaging.
        let rust_only = vec![sample("http-small-c16", RUST_LABEL, "nodelay", 200.0)];
        let summary = aggregate(&rust_only);
        assert!(
            summary
                .get("http-small-c16")
                .is_some_and(|c| c.rust_vs_go_rps.is_empty())
        );

        let rows = summary_rows(&aggregate(&samples));
        assert!(rows.iter().any(|r| r.contains("2.000x")));
        assert!(rows.iter().any(|r| r.contains(GO_LABEL)));
    }

    #[test]
    fn implementation_axis_selection_and_validation() -> Result<()> {
        assert_eq!(
            parse_server_spec("go=/tmp/gowww/www-go")?,
            ("go".to_owned(), "/tmp/gowww/www-go".to_owned())
        );
        assert!(parse_server_spec("/tmp/www-go").is_err());
        assert!(parse_server_spec("go=").is_err());
        assert!(parse_server_spec("=/tmp/x").is_err());
        assert!(parse_server_spec("go bad=/tmp/x").is_err());

        let specs = vec![
            ("go".to_owned(), "/tmp/a".to_owned()),
            ("rust-base".to_owned(), "/tmp/b".to_owned()),
        ];
        let labels = registered_labels(&specs)?;
        assert_eq!(labels, vec!["rust", "go", "rust-base"]);
        assert!(registered_labels(&[("rust".to_owned(), "/tmp/a".to_owned())]).is_err());
        assert!(
            registered_labels(&[
                ("go".to_owned(), "/tmp/a".to_owned()),
                ("go".to_owned(), "/tmp/b".to_owned()),
            ])
            .is_err()
        );

        assert_eq!(select_implementation_labels(&labels, None)?, labels);
        assert_eq!(
            select_implementation_labels(&labels, Some("go, rust"))?,
            vec!["go".to_owned(), "rust".to_owned()]
        );
        assert!(select_implementation_labels(&labels, Some("nope")).is_err());
        assert!(select_implementation_labels(&labels, Some("go,go")).is_err());
        assert!(select_implementation_labels(&labels, Some(" , ")).is_err());

        // Execution order alternates on odd rotations for both axes.
        let impls = ["rust", "go"];
        assert_eq!(alternate(&impls, false), vec!["rust", "go"]);
        assert_eq!(alternate(&impls, true), vec!["go", "rust"]);
        assert_eq!(alternate(&["rust"], true), vec!["rust"]);
        Ok(())
    }

    #[test]
    fn per_request_counter_derivation_uses_deltas() -> Result<()> {
        let io_before = parse_proc_io("rchar: 100\nwchar: 200\nsyscr: 10\nsyscw: 20\n")?;
        let io_after =
            parse_proc_io("rchar: 1100\nwchar: 2200\nsyscr: 110\nsyscw: 220\nread_bytes: 0\n")?;
        assert_eq!(io_after.rchar, 1100);
        let status_before = parse_proc_status(
            "Name:\twww\nThreads:\t4\nvoluntary_ctxt_switches:\t5\nnonvoluntary_ctxt_switches:\t1\n",
        )?;
        let status_after = parse_proc_status(
            "Name:\twww\nThreads:\t9\nvoluntary_ctxt_switches:\t105\nnonvoluntary_ctxt_switches:\t51\n",
        )?;
        assert_eq!(status_after.threads, 9);

        let deltas = CounterDeltas::between(io_before, io_after, status_before, status_after);
        assert_eq!(
            deltas,
            CounterDeltas {
                syscr: 100,
                syscw: 200,
                rchar: 1000,
                wchar: 2000,
                voluntary_ctxt_switches: 100,
                nonvoluntary_ctxt_switches: 50,
            }
        );

        let per_request = per_request_counters(deltas, 0.5, 100);
        assert!((per_request.syscalls_read - 1.0).abs() < f64::EPSILON);
        assert!((per_request.syscalls_write - 2.0).abs() < f64::EPSILON);
        assert!((per_request.context_switches - 1.5).abs() < f64::EPSILON);
        assert!((per_request.cpu_microseconds - 5000.0).abs() < f64::EPSILON);
        assert_eq!(
            per_request_counters(deltas, 0.5, 0),
            PerRequestCounters::default()
        );
        // Counter wrap or server restart never yields negative rates.
        let backwards = CounterDeltas::between(io_after, io_before, status_after, status_before);
        assert_eq!(backwards, CounterDeltas::default());
        assert!(parse_proc_io("rchar: 1\n").is_err());
        Ok(())
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
    fn case_matrix_covers_every_required_workload() -> Result<()> {
        let all_names: BTreeSet<&str> = CASES.iter().map(|c| c.name).collect();
        assert_eq!(all_names.len(), CASES.len(), "duplicate case names");

        // The original 14 cases must keep working verbatim.
        for legacy in [
            "http-small-c1",
            "http-small-c16",
            "http-small-c64",
            "http-small-c128",
            "http-medium-c16",
            "http-large-c16",
            "http-listing-c16",
            "https-small-c1",
            "https-small-c16",
            "https-small-c64",
            "https-small-c128",
            "https-medium-c16",
            "https-large-c16",
            "https-listing-c16",
        ] {
            assert!(all_names.contains(legacy), "missing legacy case {legacy}");
            assert!(select_cases("all", &[legacy.to_owned()])?.len() == 1);
        }

        for scheme in ["http", "https"] {
            let tls = scheme == "https";
            let cases: Vec<Case> = select_cases(scheme, &[])?;
            assert!(cases.iter().all(|c| c.tls == tls));
            let paths: BTreeSet<&str> = cases.iter().map(|c| c.path).collect();
            for required in ["/small.bin", "/medium.bin", "/large.bin", "/listing/"] {
                assert!(paths.contains(required), "{scheme} missing {required}");
            }
            // Concurrency coverage.
            let small: BTreeSet<usize> = cases
                .iter()
                .filter(|c| c.path == "/small.bin" && c.keepalive && c.expected_status == 200)
                .map(|c| c.concurrency)
                .collect();
            assert_eq!(small, BTreeSet::from([1, 16, 64, 128]));
            for path in ["/medium.bin", "/listing/"] {
                let concurrencies: BTreeSet<usize> = cases
                    .iter()
                    .filter(|c| c.path == path && c.method == "GET" && c.expected_status == 200)
                    .map(|c| c.concurrency)
                    .collect();
                assert!(concurrencies.contains(&16), "{scheme} {path} missing c16");
                assert!(concurrencies.contains(&64), "{scheme} {path} missing c64");
            }
            assert!(
                cases
                    .iter()
                    .any(|c| c.path == "/large.bin" && c.concurrency >= 16)
            );
            // Keep-alive on and off for the small c16 case.
            assert!(
                cases
                    .iter()
                    .any(|c| c.path == "/small.bin" && c.concurrency == 16 && c.keepalive)
            );
            assert!(
                cases
                    .iter()
                    .any(|c| c.path == "/small.bin" && c.concurrency == 16 && !c.keepalive)
            );
            // Method / status coverage.
            assert!(
                cases
                    .iter()
                    .any(|c| c.method == "HEAD" && c.expected_status == 200)
            );
            let conditional = cases.iter().find(|c| c.expected_status == 304);
            assert!(conditional.is_some_and(|c| {
                c.headers.iter().any(|(n, v)| {
                    n.eq_ignore_ascii_case("if-modified-since") && *v == FAR_FUTURE_DATE
                })
            }));
            let ranged = cases.iter().find(|c| c.expected_status == 206);
            assert!(ranged.is_some_and(|c| {
                c.path == "/large.bin" && range_header_length(c.headers) == Some(65536)
            }));
        }
        assert!(select_cases("http", &["https-small-c1".to_owned()]).is_err());
        assert!(select_cases("all", &["nope".to_owned()]).is_err());
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
            let pid = std::process::id();
            assert!(read_proc_io(pid).is_ok());
            assert!(read_proc_status(pid).is_ok_and(|s| s.threads >= 1));
        }

        let cpus = parse_cpu_list("0-3, 6, 8-9")?;
        assert_eq!(cpus, vec![0, 1, 2, 3, 6, 8, 9]);
        Ok(())
    }

    /// The load generator must never land on an SMT sibling of a server CPU:
    /// sharing a physical core makes the server's measured cost depend on the
    /// client's load.
    #[test]
    fn client_cpus_exclude_smt_siblings_of_server_cpus() -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }
        let cpus = available_cpus()?;
        if cpus.len() < 4 {
            return Ok(());
        }
        let (server, client) = split_cpus(&cpus, 2)?;
        assert_eq!(server.len(), 2);
        assert!(!client.is_empty());
        for server_cpu in &server {
            for sibling in thread_siblings(*server_cpu) {
                assert!(
                    !client.contains(&sibling),
                    "client CPU {sibling} shares a physical core with server CPU {server_cpu}"
                );
            }
        }
        // Requesting every CPU as a server CPU leaves no room for the client.
        assert!(split_cpus(&cpus, cpus.len()).is_err());
        Ok(())
    }

    /// `/proc/<pid>/status` reports the thread-group leader only; the server's
    /// work happens on its other threads, so the counters must be summed.
    #[test]
    fn context_switches_are_summed_across_server_threads() -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = thread::spawn(move || {
            // Force voluntary context switches on a thread that is not the
            // thread-group leader.
            for _ in 0..200 {
                thread::sleep(Duration::from_micros(200));
            }
            let _ = done_tx.send(());
            let _ = rx.recv();
        });
        let pid = std::process::id();
        let before = read_proc_status(pid)?;
        done_rx.recv_timeout(Duration::from_secs(10))?;
        let after = read_proc_status(pid)?;
        let leader = parse_proc_status(&fs::read_to_string(format!("/proc/{pid}/status"))?)?;
        assert!(
            after.voluntary_ctxt_switches > before.voluntary_ctxt_switches,
            "summed voluntary switches did not grow"
        );
        assert!(
            after.voluntary_ctxt_switches >= leader.voluntary_ctxt_switches,
            "summed counters must include at least the leader's"
        );
        let _ = tx.send(());
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("worker panicked"))?;
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
