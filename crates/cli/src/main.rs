//! openfd: lsof that answers instantly.
//!
//! Streams every open file descriptor of every visible process from `/proc`
//! and prints it in a human-friendly table, terse pid list, NDJSON or CSV.

use std::io;
use std::process::ExitCode;

use clap::Parser;

use openfd_core::{Backend, FdEntry, FdSink, ProcessInfo, ScanOptions};

mod filters;
mod output;

use filters::Filters;
use output::{Format, Printer};

#[derive(Debug, Parser)]
#[command(
    name = "openfd",
    version,
    about = "lsof that answers instantly: list open file descriptors of every process",
    after_help = "MVP covers the common 20% of lsof use cases. Run `openfd --help` for details."
)]
struct Args {
    /// Comma-separated pids to include (-p in lsof)
    #[arg(short = 'p', long = "pid", value_name = "PID[,PID]...")]
    pid: Option<String>,

    /// Comma-separated command names (match on comm and cmdline basename)
    #[arg(short = 'c', long = "command", value_name = "NAME[,NAME]...")]
    command: Option<String>,

    /// Comma-separated users (names or uids)
    #[arg(short = 'u', long = "user", value_name = "USER[,USER]...")]
    user: Option<String>,

    /// Comma-separated fd numbers to include
    #[arg(short = 'f', long = "fd", value_name = "FD[,FD]...")]
    fd: Option<String>,

    /// Match target paths by substring
    #[arg(long = "path", value_name = "SUBSTR[,SUBSTR]...")]
    path: Option<String>,

    /// Only fds whose target is inside DIR (lsof `+D`, non-recursive match
    /// on the path prefix; the directory itself must exist)
    #[arg(long = "dir", value_name = "DIR")]
    dir: Option<String>,

    /// Block until no entry matches the filters, then exit 0
    /// (combine with --path/--dir/-i; poll interval via --interval)
    #[arg(long = "wait")]
    wait: bool,

    /// Poll interval in seconds for --wait/--watch/--top
    #[arg(long = "interval", value_name = "SECONDS", default_value = "1")]
    interval: f64,

    /// Internet/socket filter, lsof-style: `-i` (any inet), `-i tcp`,
    /// `-i :443`, `-i tcp:443`, `-i @127.0.0.1:8080`, `-i unix`
    #[arg(short = 'i', long = "inet", value_name = "[PROTO][:PORT][@ADDR]",
          num_args = 0..=1, default_missing_value = "")]
    inet: Option<String>,

    /// Only files that were deleted while still open (reclaimable disk space)
    #[arg(short = 'd', long = "deleted")]
    deleted: bool,

    /// Print pids only
    #[arg(short = 't', long = "terse")]
    terse: bool,

    /// Per-process summary instead of one line per fd
    #[arg(short = 's', long = "summary")]
    summary: bool,

    /// Skip username resolution (numeric uids, faster)
    #[arg(short = 'n', long = "numeric")]
    numeric: bool,

    /// Stat every fd and show file sizes
    #[arg(long = "sizes")]
    sizes: bool,

    /// NDJSON output (one object per line, streaming)
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// CSV output
    #[arg(long = "csv")]
    csv: bool,
}

impl Args {
    fn format(&self) -> Format {
        if self.json {
            Format::Json
        } else if self.csv {
            Format::Csv
        } else if self.terse {
            Format::Terse
        } else {
            Format::Table
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let mut filters = Filters::default();
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

    let stdout = Box::new(io::stdout()) as Box<dyn io::Write + Send>;
    let mut printer = Printer::new(args.format(), args.summary, args.sizes, stdout);

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

fn scan_sink<'a>(printer: &'a mut Printer, filters: &'a Filters) -> Box<FdSink<'a>> {
    Box::new(move |info, entry| {
        if filters.matches(info, entry) {
            printer.write_row(info, entry);
        }
    })
}
