//! openfd: lsof that answers instantly.
//!
//! Streams every open file descriptor of every visible process from `/proc`
//! and prints it in a human-friendly table, terse pid list, NDJSON or CSV.

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

use openfd_core::{Backend, FdEntry, FdSink, ProcessInfo, ScanOptions};

use openfd::Args;
use openfd::color::{ColorMode, Colors};
use openfd::filters::Filters;
use openfd::output::Printer;

fn main() -> ExitCode {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        clap_complete::generate(
            shell,
            &mut openfd::cli_command(),
            "openfd",
            &mut io::stdout(),
        );
        return ExitCode::SUCCESS;
    }

    let mut filters = Filters::default();
    if args.tree && (args.summary || args.terse || args.json || args.csv) {
        eprintln!("openfd: --tree works with the table output only (not -s/-t/-j/--csv)");
        return ExitCode::from(2);
    }
    if let Some(spec) = &args.pid
        && let Err(e) = filters.set_pids(spec)
    {
        eprintln!("openfd: {e}");
        return ExitCode::from(2);
    }
    if let Some(spec) = &args.fd
        && let Err(e) = filters.set_fds(spec)
    {
        eprintln!("openfd: {e}");
        return ExitCode::from(2);
    }
    if let Some(spec) = &args.user {
        filters.set_users(spec);
    }
    if let Some(spec) = &args.command {
        filters.set_commands(spec);
    }
    if let Some(spec) = &args.path {
        filters.set_paths(spec);
    }
    if let Some(dir) = &args.dir {
        filters.set_dir(dir);
    }
    if let Some(spec) = &args.inet
        && let Err(e) = filters.set_inet(spec)
    {
        eprintln!("openfd: {e}");
        return ExitCode::from(2);
    }
    if args.deleted {
        filters.set_deleted();
    }

    let color_mode = match ColorMode::parse(&args.color) {
        Some(m) => m,
        None => {
            eprintln!("openfd: --color must be auto, always or never");
            return ExitCode::from(2);
        }
    };
    let colors = Colors::new(color_mode.effective());

    let mut opts = ScanOptions::new();
    if args.numeric {
        opts = opts.numeric();
    }
    if args.sizes {
        opts = opts.stat_all();
    }

    let backend = openfd_core::default_backend();
    if args.wait {
        if args.interval <= 0.0 {
            eprintln!("openfd: --interval must be positive");
            return ExitCode::from(2);
        }
        return wait_loop(backend.as_ref(), &opts, &filters, args.interval);
    }
    if let Some(spec) = &args.top {
        let n = match spec.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("openfd: --top expects a positive number, got {spec:?}");
                return ExitCode::from(2);
            }
        };
        if args.interval <= 0.0 {
            eprintln!("openfd: --interval must be positive");
            return ExitCode::from(2);
        }
        return run_top(backend.as_ref(), &opts, &filters, n, args.interval);
    }
    if args.watch {
        if args.interval <= 0.0 {
            eprintln!("openfd: --interval must be positive");
            return ExitCode::from(2);
        }
        return run_watch(backend.as_ref(), &opts, &filters, args.interval, colors);
    }

    let stdout = Box::new(io::stdout()) as Box<dyn io::Write + Send>;
    let mut printer = Printer::new(
        args.format(),
        args.summary,
        args.tree,
        args.sizes,
        colors,
        stdout,
    );

    {
        let mut sink = scan_sink(&mut printer, &filters);
        if let Err(e) = backend.scan(&opts, &mut *sink) {
            eprintln!("openfd: scan failed: {e}");
            return ExitCode::FAILURE;
        }
    }
    printer.finish();
    ExitCode::SUCCESS
}

/// Block until no entry matches the filters, then exit 0. Useful for
/// waiting on released files/ports during deploys: `openfd --wait --path X`.
fn wait_loop(
    backend: &dyn Backend,
    opts: &ScanOptions,
    filters: &Filters,
    interval: f64,
) -> ExitCode {
    loop {
        let mut matched = 0u64;
        let mut sink = |info: &std::sync::Arc<ProcessInfo>, entry: &mut FdEntry| {
            if filters.matches(info, entry) {
                matched += 1;
            }
        };
        if let Err(e) = backend.scan(opts, &mut sink) {
            eprintln!("openfd: scan failed: {e}");
            return ExitCode::FAILURE;
        }
        if matched == 0 {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(interval.max(0.05)));
    }
}

type FdCounts = std::collections::HashMap<u32, (String, String, u64)>;

/// One fd of one process, identity for the watch diff.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FdKey {
    pid: u32,
    fd: i32,
}

#[derive(Debug, Clone)]
struct FdState {
    comm: String,
    kind: &'static str,
    target: String,
    deleted: bool,
}

fn snapshot_once(
    backend: &dyn Backend,
    opts: &ScanOptions,
    filters: &Filters,
) -> io::Result<std::collections::BTreeMap<FdKey, FdState>> {
    let mut map = std::collections::BTreeMap::new();
    let mut sink = |info: &std::sync::Arc<ProcessInfo>, entry: &mut FdEntry| {
        if !filters.matches(info, entry) {
            return;
        }
        map.insert(
            FdKey {
                pid: info.pid,
                fd: entry.fd,
            },
            FdState {
                comm: info.comm.clone(),
                kind: entry.kind.tag(),
                target: entry.target.clone(),
                deleted: entry.deleted,
            },
        );
    };
    backend.scan(opts, &mut sink)?;
    Ok(map)
}

/// `--watch`: diff two consecutive scans every tick and print newly opened
/// (`+`) and closed (`-`) descriptors. Runs until interrupted: Ctrl-C uses
/// the default SIGINT disposition and terminates the process (exit 130).
fn run_watch(
    backend: &dyn Backend,
    opts: &ScanOptions,
    filters: &Filters,
    interval: f64,
    colors: Colors,
) -> ExitCode {
    let sleep = std::time::Duration::from_secs_f64(interval.max(0.05));
    let mut prev = match snapshot_once(backend, opts, filters) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("openfd: scan failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    loop {
        std::thread::sleep(sleep);
        let next = match snapshot_once(backend, opts, filters) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("openfd: scan failed: {e}");
                return ExitCode::FAILURE;
            }
        };

        let mut out = io::stdout().lock();
        for (key, state) in next.iter() {
            if !prev.contains_key(key) {
                let _ = writeln!(
                    out,
                    "{} {:>6} {:<5} {:<19} {:<8} {}",
                    colors.opened("+"),
                    key.pid,
                    key.fd,
                    state.comm,
                    state.kind,
                    watch_target(state)
                );
            }
        }
        for (key, state) in prev.iter() {
            if !next.contains_key(key) {
                let _ = writeln!(
                    out,
                    "{} {:>6} {:<5} {:<19} {:<8} {}",
                    colors.closed("-"),
                    key.pid,
                    key.fd,
                    state.comm,
                    state.kind,
                    watch_target(state)
                );
            }
        }
        let _ = out.flush();
        prev = next;
    }
}

fn watch_target(state: &FdState) -> String {
    if state.deleted {
        format!("{} (deleted)", state.target)
    } else {
        state.target.clone()
    }
}

fn count_once(
    backend: &dyn Backend,
    opts: &ScanOptions,
    filters: &Filters,
) -> io::Result<FdCounts> {
    let mut counts: FdCounts = std::collections::HashMap::new();
    let mut sink = |info: &std::sync::Arc<ProcessInfo>, entry: &mut FdEntry| {
        if !filters.matches(info, entry) {
            return;
        }
        let user = match &info.username {
            Some(name) => name.clone(),
            None => info.uid.to_string(),
        };
        counts
            .entry(info.pid)
            .and_modify(|(comm, u, c)| {
                *c += 1;
                *comm = info.comm.clone();
                *u = user.clone();
            })
            .or_insert((info.comm.clone(), user, 1));
    };
    backend.scan(opts, &mut sink)?;
    Ok(counts)
}

/// `--top`: two scans `interval` seconds apart; report the processes whose
/// fd count grew the most. A leak shows up as steady growth - run it again
/// with a larger interval to confirm the trend.
fn run_top(
    backend: &dyn Backend,
    opts: &ScanOptions,
    filters: &Filters,
    n: usize,
    interval: f64,
) -> ExitCode {
    let first = match count_once(backend, opts, filters) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("openfd: scan failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    std::thread::sleep(std::time::Duration::from_secs_f64(interval.max(0.05)));
    let second = match count_once(backend, opts, filters) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("openfd: scan failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut rows: Vec<(u32, String, String, u64, i64)> = second
        .iter()
        .map(|(pid, (comm, user, count))| {
            let before = first.get(pid).map(|(_, _, c)| *c).unwrap_or(0);
            let delta = *count as i64 - before as i64;
            (*pid, comm.clone(), user.clone(), *count, delta)
        })
        .filter(|(_, _, _, _, delta)| *delta != 0)
        .collect();
    rows.sort_by(|a, b| b.4.cmp(&a.4).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(n);

    let mut out = io::stdout().lock();
    let _ = writeln!(
        out,
        "{:<7} {:<12} {:<19} {:>6} {:>7}",
        "PID", "USER", "COMMAND", "FDS", "DELTA"
    );
    for (pid, comm, user, count, delta) in rows {
        let comm = comm.chars().take(19).collect::<String>();
        let user = user.chars().take(12).collect::<String>();
        let _ = writeln!(out, "{pid:<7} {user:<12} {comm:<19} {count:>6} {delta:>+7}");
    }
    ExitCode::SUCCESS
}

fn scan_sink<'a>(printer: &'a mut Printer, filters: &'a Filters) -> Box<FdSink<'a>> {
    Box::new(move |info, entry| {
        if filters.matches(info, entry) {
            printer.write_row(info, entry);
        }
    })
}
