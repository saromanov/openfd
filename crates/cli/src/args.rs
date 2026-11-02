//! The clap `Args` definition, shared by the `openfd` binary, the man-page
//! generator and shell completions.

use clap::Parser;

use crate::output::Format;

#[derive(Debug, Parser)]
#[command(
    name = "openfd",
    version,
    about = "lsof that answers instantly: list open file descriptors of every process",
    after_help = "MVP covers the common 20% of lsof use cases. Run `openfd --help` for details."
)]
pub struct Args {
    /// Comma-separated pids to include (-p in lsof)
    #[arg(short = 'p', long = "pid", value_name = "PID[,PID]...")]
    pub pid: Option<String>,

    /// Comma-separated command names (match on comm and cmdline basename)
    #[arg(short = 'c', long = "command", value_name = "NAME[,NAME]...")]
    pub command: Option<String>,

    /// Comma-separated users (names or uids)
    #[arg(short = 'u', long = "user", value_name = "USER[,USER]...")]
    pub user: Option<String>,

    /// Comma-separated fd numbers to include
    #[arg(short = 'f', long = "fd", value_name = "FD[,FD]...")]
    pub fd: Option<String>,

    /// Match target paths by substring
    #[arg(long = "path", value_name = "SUBSTR[,SUBSTR]...")]
    pub path: Option<String>,

    /// Only fds whose target is inside DIR (lsof `+D`, non-recursive match
    /// on the path prefix; the directory itself must exist)
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<String>,

    /// Block until no entry matches the filters, then exit 0
    /// (combine with --path/--dir/-i; poll interval via --interval)
    #[arg(long = "wait")]
    pub wait: bool,

    /// Poll interval in seconds for --wait/--watch/--top
    #[arg(long = "interval", value_name = "SECONDS", default_value = "1")]
    pub interval: f64,

    /// Internet/socket filter, lsof-style: `-i` (any inet), `-i tcp`,
    /// `-i :443`, `-i tcp:443`, `-i @127.0.0.1:8080`, `-i unix`
    #[arg(short = 'i', long = "inet", value_name = "[PROTO][:PORT][@ADDR]",
          num_args = 0..=1, default_missing_value = "")]
    pub inet: Option<String>,

    /// Only files that were deleted while still open (reclaimable disk space)
    #[arg(short = 'd', long = "deleted")]
    pub deleted: bool,

    /// Print pids only
    #[arg(short = 't', long = "terse")]
    pub terse: bool,

    /// Per-process summary instead of one line per fd
    #[arg(short = 's', long = "summary")]
    pub summary: bool,

    /// Group output as a process tree (table format only)
    #[arg(long = "tree")]
    pub tree: bool,

    /// fd-leak detector: scan twice (interval apart), print the top N
    /// processes by fd growth. [N] defaults to 10.
    #[arg(long = "top", value_name = "N", num_args = 0..=1, default_missing_value = "10")]
    pub top: Option<String>,

    /// Live mode: on every tick print newly opened (+) and closed (-) fds
    /// that match the filters; runs until interrupted
    #[arg(long = "watch")]
    pub watch: bool,

    /// Skip username resolution (numeric uids, faster)
    #[arg(short = 'n', long = "numeric")]
    pub numeric: bool,

    /// Stat every fd and show file sizes
    #[arg(long = "sizes")]
    pub sizes: bool,

    /// NDJSON output (one object per line, streaming)
    #[arg(short = 'j', long = "json")]
    pub json: bool,

    /// CSV output
    #[arg(long = "csv")]
    pub csv: bool,

    /// When to color the output: auto (default), always, never
    #[arg(long = "color", value_name = "WHEN", default_value = "auto")]
    pub color: String,

    /// Print a shell completion script (bash, zsh, fish, powershell) and exit
    #[arg(long = "completions", value_name = "SHELL")]
    pub completions: Option<clap_complete::Shell>,
}

impl Args {
    pub fn format(&self) -> Format {
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

/// The full clap command (name, version, args), used by `--completions`
/// and the man-page generator.
pub fn cli_command() -> clap::Command {
    <Args as clap::Args>::augment_args(clap::Command::new("openfd"))
}
