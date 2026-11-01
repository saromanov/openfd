//! openfd: lsof that answers instantly.
//!
//! Streams every open file descriptor of every visible process from `/proc`
//! and prints it in a human-friendly table, terse pid list, NDJSON or CSV.

use std::io;
use std::process::ExitCode;

use clap::Parser;

use openfd_core::{FdSink, ScanOptions};

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

    let stdout = Box::new(io::stdout()) as Box<dyn io::Write + Send>;
    let mut printer = Printer::new(args.format(), args.summary, args.sizes, stdout);

    let backend = openfd_core::default_backend();
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

fn scan_sink<'a>(printer: &'a mut Printer, filters: &'a Filters) -> Box<FdSink<'a>> {
    Box::new(move |info, entry| {
        if filters.matches(info, entry) {
            printer.write_row(info, entry);
        }
    })
}
