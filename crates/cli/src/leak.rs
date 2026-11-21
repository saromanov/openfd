//! `openfd leak`: watch processes over time and diagnose fd growth.
//!
//! Replaces the usual `while sleep 10; do ls /proc/$PID/fd | wc -l; done`
//! script with a limit-aware report: growth rate, R², ETA to `EMFILE`, what
//! grew (by signature) and a verdict naming the likely bug.
//!
//! Read-only: nothing is restarted, killed or truncated.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use openfd_core::leak::{
    Fit, Sample, dominant, eta_seconds, fd_signature, linear_fit, read_limit, verdict,
};
use openfd_core::owner::{Owner, OwnerKind, parse_cgroup};
use openfd_core::passwd::UserTable;
use openfd_core::{Backend, FdEntry, FdSink, ProcessFilter, ProcessInfo, ScanOptions};

use crate::args::LeakArgs;
use crate::filters::Filters;

const EXIT_OK: u8 = 0;
const EXIT_LEAK: u8 = 1;
const EXIT_ERROR: u8 = 2;
const EXIT_ETA_BREACH: u8 = 3;

/// Parse `500ms`, `5s`, `1m`, `2h`, `1d`, or plain seconds.
pub fn parse_duration(spec: &str) -> Result<Duration, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty duration".to_string());
    }
    let (number, unit) = if let Some(rest) = spec.strip_suffix("ms") {
        (rest, 0.001)
    } else if let Some(rest) = spec.strip_suffix('s') {
        (rest, 1.0)
    } else if let Some(rest) = spec.strip_suffix('m') {
        (rest, 60.0)
    } else if let Some(rest) = spec.strip_suffix('h') {
        (rest, 3600.0)
    } else if let Some(rest) = spec.strip_suffix('d') {
        (rest, 86_400.0)
    } else {
        (spec, 1.0)
    };
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration: {spec:?}"))?;
    if !value.is_finite() || value <= 0.0 {
        return Err(format!("duration must be positive: {spec:?}"));
    }
    Ok(Duration::from_secs_f64(value * unit))
}

/// `24h 55m`, `3m 20s`, `900ms` - compact enough for the report header.
pub fn format_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds < 0.0 {
        return "unknown".to_string();
    }
    let total = seconds.round() as u64;
    let d = total / 86_400;
    let h = (total % 86_400) / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if d > 0 {
        if h > 0 {
            format!("{d}d {h}h")
        } else {
            format!("{d}d")
        }
    } else if h > 0 {
        if m > 0 {
            format!("{h}h {m}m")
        } else {
            format!("{h}h")
        }
    } else if m > 0 {
        if s > 0 {
            format!("{m}m {s}s")
        } else {
            format!("{m}m")
        }
    } else {
        format!("{s}s")
    }
}

/// `8 412`: thin-space grouping keeps large fd counts readable.
pub fn format_count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

/// One snapshot of one process.
#[derive(Debug, Clone)]
struct ProcSample {
    comm: String,
    uid: u32,
    fds: u64,
    limit: Option<u64>,
    owner: Option<Owner>,
    signatures: HashMap<String, u64>,
}

impl ProcSample {
    fn new(comm: String, uid: u32, limit: Option<u64>, owner: Option<Owner>) -> Self {
        ProcSample {
            comm,
            uid,
            fds: 0,
            limit,
            owner,
            signatures: HashMap::new(),
        }
    }
}

/// One leaking process.
#[derive(Debug, Clone)]
struct Leak {
    pid: u32,
    comm: String,
    uid: u32,
    owner: Option<Owner>,
    fds: u64,
    limit: Option<u64>,
    fit: Fit,
    eta: Option<f64>,
    /// Signature deltas since the first sample, largest first.
    breakdown: Vec<(String, u64)>,
}

impl Leak {
    fn verdict(&self) -> &'static str {
        match dominant(&self.breakdown) {
            Some(signature) => verdict(signature),
            None => "growth detected, but no single fd signature dominates",
        }
    }
}

/// Metadata for one observation window.
struct Window {
    started: Instant,
    series: BTreeMap<u32, Vec<Sample>>,
    first_signatures: HashMap<u32, HashMap<String, u64>>,
    last: HashMap<u32, ProcSample>,
    samples: usize,
    observed: usize,
}

impl Window {
    fn new() -> Self {
        Window {
            started: Instant::now(),
            series: BTreeMap::new(),
            first_signatures: HashMap::new(),
            last: HashMap::new(),
            samples: 0,
            observed: 0,
        }
    }

    fn record(&mut self, snapshot: HashMap<u32, ProcSample>) {
        let elapsed = self.started.elapsed().as_secs_f64();
        self.samples += 1;
        self.observed = self.observed.max(snapshot.len());
        for (pid, sample) in &snapshot {
            self.series.entry(*pid).or_default().push(Sample {
                seconds: elapsed,
                fds: sample.fds,
            });
            self.first_signatures
                .entry(*pid)
                .or_insert_with(|| sample.signatures.clone());
        }
        self.last = snapshot;
    }

    fn candidates(&self) -> usize {
        self.series
            .values()
            .filter(|points| {
                points.len() >= 2 && points.last().map(|p| p.fds) > points.first().map(|p| p.fds)
            })
            .count()
    }
}

pub fn run(args: LeakArgs) -> ExitCode {
    if let Some(nice) = args.nice {
        // Lower our own priority before sampling starts. Failure is not
        // fatal: an unprivileged decrease always succeeds.
        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice as i32) };
        if rc != 0 {
            eprintln!("openfd: warning: could not set nice {nice}");
        }
    }

    let interval = match parse_duration(&args.interval) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("openfd: --interval: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let duration = match parse_duration(&args.duration) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("openfd: --duration: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let fail_eta = match args.fail_if_eta.as_deref().map(parse_duration) {
        Some(Ok(d)) => Some(d.as_secs_f64()),
        Some(Err(e)) => {
            eprintln!("openfd: --fail-if-eta: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
        None => None,
    };
    if args.min_samples < 2 {
        eprintln!("openfd: --min-samples must be at least 2");
        return ExitCode::from(EXIT_ERROR);
    }
    if args.top == 0 {
        eprintln!("openfd: --top must be at least 1");
        return ExitCode::from(EXIT_ERROR);
    }
    if !args.min_rate.is_finite() || args.min_rate < 0.0 {
        eprintln!("openfd: --min-rate must be a non-negative number");
        return ExitCode::from(EXIT_ERROR);
    }

    let filters = match build_filters(&args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("openfd: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let shared = Arc::new(filters);
    let scan_opts = ScanOptions::new()
        .no_fdinfo()
        .process_filter(shared as Arc<dyn ProcessFilter>);

    let backend = openfd_core::default_backend();
    let users = UserTable::load();
    let mut caches = Caches::default();
    let tty = io::stdout().is_terminal() && !args.json;

    loop {
        let mut window = Window::new();
        if let Err(e) = observe(
            backend.as_ref(),
            &scan_opts,
            interval,
            duration,
            tty,
            &mut window,
            &mut caches,
        ) {
            eprintln!("openfd: scan failed: {e}");
            return ExitCode::from(EXIT_ERROR);
        }

        let leaks = analyze(
            &window.series,
            &window.first_signatures,
            &window.last,
            args.min_samples,
            args.min_rate,
            args.top,
        );

        if !args.json {
            println!(
                "observed {} processes for {} ({} samples); {} leaking",
                format_count(window.observed as u64),
                format_duration(window.started.elapsed().as_secs_f64()),
                window.samples,
                leaks.len()
            );
            let mut out = io::stdout().lock();
            for leak in &leaks {
                if let Err(e) = write_leak(&mut out, leak, &users) {
                    eprintln!("openfd: write failed: {e}");
                    return ExitCode::from(EXIT_ERROR);
                }
            }
            let _ = out.flush();
        } else if let Err(e) = write_json(&mut io::stdout().lock(), &window, &leaks, &users) {
            eprintln!("openfd: write failed: {e}");
            return ExitCode::from(EXIT_ERROR);
        }

        let breached = fail_eta
            .is_some_and(|limit| leaks.iter().any(|l| l.eta.is_some_and(|eta| eta <= limit)));
        if breached {
            return ExitCode::from(EXIT_ETA_BREACH);
        }
        if !args.follow {
            return if leaks.is_empty() {
                ExitCode::from(EXIT_OK)
            } else {
                ExitCode::from(EXIT_LEAK)
            };
        }
        // --follow: start a fresh window and keep printing reports.
    }
}

fn build_filters(args: &LeakArgs) -> Result<Filters, String> {
    let mut filters = Filters::default();
    if let Some(spec) = &args.pid {
        filters.set_pids(spec)?;
    }
    if let Some(spec) = &args.user {
        filters.set_users(spec);
    }
    if let Some(spec) = &args.command {
        filters.set_commands(spec);
    }
    Ok(filters)
}

#[derive(Default)]
struct Caches {
    limits: HashMap<u32, Option<u64>>,
    owners: HashMap<u32, Option<Owner>>,
}

fn read_owner(pid: u32) -> Option<Owner> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .map(|content| parse_cgroup(&content))
}

/// Sleep until the next tick, then take one snapshot.
fn observe(
    backend: &dyn Backend,
    opts: &ScanOptions,
    interval: Duration,
    duration: Duration,
    tty: bool,
    window: &mut Window,
    caches: &mut Caches,
) -> io::Result<()> {
    // Samples at t = 0, interval, 2*interval... fit inside the window.
    let ticks = ((duration.as_secs_f64() / interval.as_secs_f64()).floor() as usize).max(1);
    for tick in 0..ticks {
        if tick > 0 {
            std::thread::sleep(interval);
        }
        let snapshot = sample_once(backend, opts, caches)?;
        window.record(snapshot);
        if tty {
            let mut out = io::stdout().lock();
            let _ = write!(
                out,
                "\rsampling {} processes every {}… {}/{} samples, {} candidates\u{1b}[K",
                format_count(window.observed as u64),
                format_duration(interval.as_secs_f64()),
                window.samples,
                ticks,
                window.candidates()
            );
            let _ = out.flush();
        }
    }
    if tty {
        println!();
    }
    Ok(())
}

fn sample_once(
    backend: &dyn Backend,
    opts: &ScanOptions,
    caches: &mut Caches,
) -> io::Result<HashMap<u32, ProcSample>> {
    let samples: Mutex<HashMap<u32, ProcSample>> = Mutex::new(HashMap::new());
    let sink: Box<FdSink<'_>> = Box::new(|info: &Arc<ProcessInfo>, entry: &FdEntry| {
        let mut guard = samples.lock().unwrap();
        let sample = guard.entry(info.pid).or_insert_with(|| {
            // The limit/owner caches are only touched from this thread; each
            // scan runs the sink from its workers, so go through the cache
            // under the same mutex via a local reset below.
            ProcSample::new(info.comm.clone(), info.uid, None, None)
        });
        sample.fds += 1;
        *sample.signatures.entry(fd_signature(entry)).or_insert(0) += 1;
    });
    backend.scan(opts, &sink)?;
    drop(sink);

    let mut samples = samples.into_inner().unwrap();
    // Limits and the cgroup owner rarely change: read them once per pid and
    // reuse the cached values for every following sample.
    let pids: Vec<u32> = samples.keys().copied().collect();
    for pid in pids {
        let limit = *caches.limits.entry(pid).or_insert_with(|| read_limit(pid));
        let owner = caches
            .owners
            .entry(pid)
            .or_insert_with(|| read_owner(pid))
            .clone();
        if let Some(sample) = samples.get_mut(&pid) {
            sample.limit = limit;
            sample.owner = owner;
        }
    }
    Ok(samples)
}

fn analyze(
    series: &BTreeMap<u32, Vec<Sample>>,
    first_signatures: &HashMap<u32, HashMap<String, u64>>,
    last: &HashMap<u32, ProcSample>,
    min_samples: usize,
    min_rate: f64,
    top: usize,
) -> Vec<Leak> {
    let mut leaks = Vec::new();
    for (pid, points) in series {
        let Some(current) = last.get(pid) else {
            continue; // the process exited during the window
        };
        if points.len() < min_samples {
            continue;
        }
        let Some(fit) = linear_fit(points) else {
            continue;
        };
        if fit.rate_per_min < min_rate || fit.rate_per_min <= 0.0 {
            continue;
        }
        let first = first_signatures.get(pid);
        let mut breakdown: Vec<(String, u64)> = current
            .signatures
            .iter()
            .map(|(signature, count)| {
                let before = first.and_then(|m| m.get(signature)).copied().unwrap_or(0);
                (signature.clone(), count.saturating_sub(before))
            })
            .filter(|(_, delta)| *delta > 0)
            .collect();
        breakdown.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        breakdown.truncate(5);

        leaks.push(Leak {
            pid: *pid,
            comm: current.comm.clone(),
            uid: current.uid,
            owner: current.owner.clone(),
            fds: current.fds,
            limit: current.limit,
            fit,
            eta: current
                .limit
                .and_then(|limit| eta_seconds(current.fds, limit, fit.rate_per_min)),
            breakdown,
        });
    }

    leaks.sort_by(|a, b| {
        a.eta
            .partial_cmp(&b.eta)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.fit.rate_per_min.partial_cmp(&a.fit.rate_per_min).unwrap())
            .then_with(|| a.pid.cmp(&b.pid))
    });
    leaks.truncate(top);
    leaks
}

fn owner_label(owner: &Option<Owner>) -> Option<String> {
    match owner {
        Some(o) if o.kind != OwnerKind::Unknown => Some(o.label()),
        _ => None,
    }
}

fn write_leak(out: &mut dyn Write, leak: &Leak, users: &UserTable) -> io::Result<()> {
    let user = users
        .name(leak.uid)
        .map(str::to_string)
        .unwrap_or_else(|| leak.uid.to_string());
    let owner = owner_label(&leak.owner);
    writeln!(out)?;
    match &owner {
        Some(label) => writeln!(out, "pid {}  {}  ({user}, {label})", leak.pid, leak.comm)?,
        None => writeln!(out, "pid {}  {}  ({user})", leak.pid, leak.comm)?,
    }

    match leak.limit {
        Some(limit) if limit > 0 => {
            let percent = leak.fds as f64 / limit as f64 * 100.0;
            writeln!(
                out,
                "  fds        {} / {} soft limit  ({percent:.1}%)",
                format_count(leak.fds),
                format_count(limit)
            )?;
        }
        _ => writeln!(out, "  fds        {}", format_count(leak.fds))?,
    }

    let shape = if leak.fit.r2 >= 0.8 {
        "steady"
    } else {
        "noisy"
    };
    writeln!(
        out,
        "  growth     {:+.1} fd/min  ({shape}, R²={:.2})",
        leak.fit.rate_per_min, leak.fit.r2
    )?;

    match leak.eta {
        Some(eta) => writeln!(out, "  ETA        ~{} to EMFILE", format_duration(eta))?,
        None => writeln!(out, "  ETA        unknown (no usable soft limit)")?,
    }

    if !leak.breakdown.is_empty() {
        writeln!(out, "  breakdown  (new fds since start, by signature)")?;
        for (signature, delta) in &leak.breakdown {
            writeln!(out, "    +{delta:<6} {signature}")?;
        }
    }
    writeln!(out, "  verdict    {}", leak.verdict())
}

// ---- JSON ----

#[derive(Debug, Serialize)]
struct JsonOwner {
    kind: &'static str,
    name: String,
}

#[derive(Debug, Serialize)]
struct JsonBreakdown {
    signature: String,
    delta: u64,
}

#[derive(Debug, Serialize)]
struct JsonLeak<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    pid: u32,
    comm: &'a str,
    user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<JsonOwner>,
    fds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
    rate_per_min: f64,
    r2: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_seconds: Option<f64>,
    verdict: &'static str,
    breakdown: Vec<JsonBreakdown>,
}

#[derive(Debug, Serialize)]
struct JsonSummary {
    #[serde(rename = "type")]
    kind: &'static str,
    processes: usize,
    samples: usize,
    window_seconds: f64,
    leaking: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    worst_eta_seconds: Option<f64>,
}

fn write_json(
    out: &mut dyn Write,
    window: &Window,
    leaks: &[Leak],
    users: &UserTable,
) -> io::Result<()> {
    for leak in leaks {
        let row = JsonLeak {
            kind: "leak",
            pid: leak.pid,
            comm: &leak.comm,
            user: users
                .name(leak.uid)
                .map(str::to_string)
                .unwrap_or_else(|| leak.uid.to_string()),
            owner: leak.owner.as_ref().and_then(|o| {
                (o.kind != OwnerKind::Unknown).then(|| JsonOwner {
                    kind: o.kind.tag(),
                    name: o.name.clone(),
                })
            }),
            fds: leak.fds,
            limit: leak.limit,
            rate_per_min: leak.fit.rate_per_min,
            r2: leak.fit.r2,
            eta_seconds: leak.eta,
            verdict: leak.verdict(),
            breakdown: leak
                .breakdown
                .iter()
                .map(|(signature, delta)| JsonBreakdown {
                    signature: signature.clone(),
                    delta: *delta,
                })
                .collect(),
        };
        serde_json::to_writer(&mut *out, &row)?;
        out.write_all(b"\n")?;
    }
    let summary = JsonSummary {
        kind: "summary",
        processes: window.observed,
        samples: window.samples,
        window_seconds: window.started.elapsed().as_secs_f64(),
        leaking: leaks.len(),
        worst_eta_seconds: leaks.iter().filter_map(|l| l.eta).reduce(f64::min),
    };
    serde_json::to_writer(&mut *out, &summary)?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Pids in a series (deterministic order), used by tests.
#[allow(dead_code)]
fn pids(series: &BTreeMap<u32, Vec<Sample>>) -> HashSet<u32> {
    series.keys().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seconds: f64, fds: u64) -> Sample {
        Sample { seconds, fds }
    }

    fn proc(fds: u64, limit: Option<u64>, signatures: &[(&str, u64)]) -> ProcSample {
        let mut p = ProcSample::new("app".to_string(), 1000, limit, None);
        p.fds = fds;
        for (signature, count) in signatures {
            p.signatures.insert(signature.to_string(), *count);
        }
        p
    }

    #[test]
    fn durations_parse_all_documented_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("0.25s").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("12").unwrap(), Duration::from_secs(12));
    }

    #[test]
    fn bad_durations_are_rejected() {
        for spec in ["", "abc", "0s", "-5s", "1x", "inf"] {
            assert!(parse_duration(spec).is_err(), "{spec:?}");
        }
    }

    #[test]
    fn durations_are_formatted_compactly() {
        assert_eq!(format_duration(0.0), "0s");
        assert_eq!(format_duration(59.0), "59s");
        assert_eq!(format_duration(90.0), "1m 30s");
        assert_eq!(format_duration(3600.0), "1h");
        assert_eq!(format_duration(3661.0), "1h 1m");
        assert_eq!(format_duration(90_000.0), "1d 1h");
        assert_eq!(format_duration(f64::INFINITY), "unknown");
        assert_eq!(format_duration(-1.0), "unknown");
    }

    #[test]
    fn counts_are_grouped_in_threes() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1000), "1 000");
        assert_eq!(format_count(8412), "8 412");
        assert_eq!(format_count(1_234_567), "1 234 567");
    }

    #[test]
    fn analysis_finds_a_steady_leak_and_ranks_by_eta() {
        let mut series = BTreeMap::new();
        series.insert(
            10,
            vec![sample(0.0, 100), sample(60.0, 160), sample(120.0, 220)],
        );
        series.insert(
            20,
            vec![sample(0.0, 10), sample(60.0, 20), sample(120.0, 30)],
        );
        series.insert(30, vec![sample(0.0, 5), sample(60.0, 5), sample(120.0, 5)]);

        let mut last = HashMap::new();
        last.insert(
            10,
            proc(220, Some(300), &[("tcp -> 10.0.0.5 CLOSE-WAIT", 120)]),
        );
        last.insert(20, proc(30, Some(10_000), &[("/var/log/x", 20)]));
        last.insert(30, proc(5, Some(100), &[]));

        let mut first = HashMap::new();
        first.insert(
            10,
            HashMap::from([("tcp -> 10.0.0.5 CLOSE-WAIT".to_string(), 0)]),
        );
        first.insert(20, HashMap::from([("/var/log/x".to_string(), 0)]));

        let leaks = analyze(&series, &first, &last, 3, 1.0, 5);
        assert_eq!(leaks.len(), 2, "the flat process must be ignored");
        assert_eq!(leaks[0].pid, 10, "the closest ETA ranks first");
        assert_eq!(leaks[0].eta, Some(80.0));
        assert_eq!(leaks[0].breakdown[0].1, 120);
        assert!(leaks[0].verdict().contains("CLOSE-WAIT"));
        assert_eq!(leaks[1].pid, 20);
        assert!(leaks[1].verdict().contains("file growth"));
    }

    #[test]
    fn analysis_respects_min_samples_and_min_rate() {
        let mut series = BTreeMap::new();
        series.insert(1, vec![sample(0.0, 0), sample(60.0, 60)]);
        let last = HashMap::from([(1, proc(60, Some(1000), &[]))]);
        let first = HashMap::new();
        assert!(analyze(&series, &first, &last, 3, 1.0, 5).is_empty());
        assert_eq!(analyze(&series, &first, &last, 2, 1.0, 5).len(), 1);
        assert!(analyze(&series, &first, &last, 2, 61.0, 5).is_empty());
        assert_eq!(analyze(&series, &first, &last, 2, 1.0, 5).len(), 1);
        assert!(analyze(&series, &first, &last, 2, 1.0, 5)[0].eta.is_some());
        assert!(analyze(&series, &first, &last, 2, 1.0, 5).len() <= 5);
    }

    #[test]
    fn exited_processes_are_skipped() {
        let mut series = BTreeMap::new();
        series.insert(1, vec![sample(0.0, 0), sample(60.0, 60)]);
        let leaks = analyze(&series, &HashMap::new(), &HashMap::new(), 2, 1.0, 5);
        assert!(leaks.is_empty());
    }

    #[test]
    fn top_limit_is_applied() {
        let mut series = BTreeMap::new();
        let mut last = HashMap::new();
        for pid in 1..=10 {
            series.insert(pid, vec![sample(0.0, 0), sample(60.0, 60)]);
            last.insert(pid, proc(60, Some(1000), &[]));
        }
        let leaks = analyze(&series, &HashMap::new(), &last, 2, 1.0, 3);
        assert_eq!(leaks.len(), 3);
    }

    #[test]
    fn no_limit_reports_an_unknown_eta() {
        let mut series = BTreeMap::new();
        series.insert(1, vec![sample(0.0, 0), sample(60.0, 60)]);
        let last = HashMap::from([(1, proc(60, None, &[]))]);
        let leaks = analyze(&series, &HashMap::new(), &last, 2, 1.0, 5);
        assert_eq!(leaks[0].limit, None);
        assert_eq!(leaks[0].eta, None);
    }

    #[test]
    fn breakdown_only_counts_new_fds() {
        let mut series = BTreeMap::new();
        series.insert(1, vec![sample(0.0, 10), sample(60.0, 40)]);
        let last = HashMap::from([(
            1,
            proc(
                40,
                Some(100), // 60 fd/min -> 60 s to EMFILE
                &[("tcp *:80 LISTEN", 30), ("pipe", 3)],
            ),
        )]);
        let first = HashMap::from([(
            1,
            HashMap::from([
                ("tcp *:80 LISTEN".to_string(), 5u64),
                ("pipe".to_string(), 3),
            ]),
        )]);
        let leaks = analyze(&series, &first, &last, 2, 1.0, 5);
        assert_eq!(
            leaks[0].breakdown,
            vec![("tcp *:80 LISTEN".to_string(), 25)]
        );
    }

    #[test]
    fn report_rendering_contains_growth_eta_and_verdict() {
        let mut series = BTreeMap::new();
        series.insert(
            3120,
            vec![sample(0.0, 100), sample(60.0, 160), sample(120.0, 220)],
        );
        let last = HashMap::from([(
            3120,
            proc(220, Some(300), &[("tcp -> 10.0.0.5 CLOSE-WAIT", 120)]),
        )]);
        let leaks = analyze(&series, &HashMap::new(), &last, 2, 1.0, 5);
        let users = UserTable::load();
        let mut out = Vec::new();
        write_leak(&mut out, &leaks[0], &users).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("pid 3120  app"), "{text}");
        assert!(
            text.contains("fds        220 / 300 soft limit  (73.3%)"),
            "{text}"
        );
        assert!(text.contains("growth     +60.0 fd/min"), "{text}");
        assert!(text.contains("R²=1.00"), "{text}");
        assert!(text.contains("ETA        ~1m 20s to EMFILE"), "{text}");
        assert!(
            text.contains("+120    tcp -> 10.0.0.5 CLOSE-WAIT"),
            "{text}"
        );
        assert!(
            text.contains("verdict    CLOSE-WAIT accumulation"),
            "{text}"
        );
    }

    #[test]
    fn report_without_limit_or_breakdown_is_honest() {
        let leak = Leak {
            pid: 5,
            comm: "app".to_string(),
            uid: u32::MAX - 1,
            owner: Some(Owner {
                kind: OwnerKind::Docker,
                name: "3f2a9c".to_string(),
                container_id: None,
                cgroup: String::new(),
            }),
            fds: 5,
            limit: None,
            fit: Fit {
                rate_per_min: 2.0,
                r2: 0.4,
            },
            eta: None,
            breakdown: Vec::new(),
        };
        let mut out = Vec::new();
        write_leak(&mut out, &leak, &UserTable::default()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("docker:3f2a9c"), "{text}");
        assert!(text.contains("noisy"), "{text}");
        assert!(text.contains("unknown (no usable soft limit)"), "{text}");
        assert!(text.contains("no single fd signature dominates"), "{text}");
    }

    #[test]
    fn json_report_has_leak_and_summary_rows() {
        let mut window = Window::new();
        window.samples = 3;
        window.observed = 42;
        window.record(HashMap::from([(1, proc(10, Some(100), &[("pipe", 10)]))]));
        let mut series = BTreeMap::new();
        series.insert(1, vec![sample(0.0, 0), sample(60.0, 60)]);
        let last = HashMap::from([(1, proc(10, Some(100), &[("pipe", 10)]))]);
        let leaks = analyze(&series, &HashMap::new(), &last, 2, 1.0, 5);
        let users = UserTable::load();
        let mut out = Vec::new();
        write_json(&mut out, &window, &leaks, &users).unwrap();
        let text = String::from_utf8(out).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows[0]["type"], "leak");
        assert_eq!(rows[0]["breakdown"][0]["signature"], "pipe");
        assert_eq!(rows[1]["type"], "summary");
        assert_eq!(rows[1]["leaking"], 1);
    }

    #[test]
    fn filter_building_rejects_bad_pids() {
        let args = LeakArgs {
            pid: Some("oops".to_string()),
            command: None,
            user: None,
            interval: "5s".to_string(),
            duration: "60s".to_string(),
            follow: false,
            min_samples: 6,
            min_rate: 1.0,
            top: 5,
            fail_if_eta: None,
            json: false,
            nice: None,
        };
        assert!(build_filters(&args).is_err());
        let mut ok = args;
        ok.pid = Some("1,2".to_string());
        assert!(build_filters(&ok).is_ok());
    }

    #[test]
    fn pids_helper_lists_the_series() {
        let mut series = BTreeMap::new();
        series.insert(7, vec![sample(0.0, 1)]);
        assert!(pids(&series).contains(&7));
    }
}
