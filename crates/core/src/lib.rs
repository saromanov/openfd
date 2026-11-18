//! openfd-core: streaming file-descriptor scanner for Linux.
//!
//! The crate reads `/proc` directly (no fork/exec, no external tools) and
//! streams one [`FdEntry`] per open descriptor through a callback, so callers
//! can start printing before the scan finishes — even on systems with
//! hundreds of thousands of open fds.
//!
//! Platform specifics live behind the [`Backend`] trait. Linux ships the
//! [`ProcBackend`]; a macOS libproc backend may join later without any change
//! to the CLI layer.
//!
//! The core contains no unsafe code and performs no network access.

mod classify;

pub mod passwd;
pub mod scanner;
pub mod sockdiag;
pub mod types;

pub use types::{
    AddrFamily, Backend, FdEntry, FdKind, FdSink, ProcessFilter, ProcessInfo, ScanOptions,
    SockAddr, SockInfo, SockProto, SockScope,
};

/// The backend for the current platform.
pub fn default_backend() -> Box<dyn Backend> {
    Box::new(scanner::ProcBackend::new())
}

/// Convenience wrapper: scan with [`default_backend`].
pub fn scan(opts: &ScanOptions, sink: &FdSink<'_>) -> std::io::Result<()> {
    default_backend().scan(opts, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn scan_wrapper_streams_into_the_sink() {
        let seen = AtomicUsize::new(0);
        let sink = |_info: &Arc<ProcessInfo>, _entry: &FdEntry| {
            seen.fetch_add(1, Ordering::Relaxed);
        };
        let opts = ScanOptions::new()
            .no_sockets()
            .parallel_min_pids(usize::MAX);
        scan(&opts, &sink).expect("scan must succeed");
        assert!(seen.into_inner() > 0, "our own fds are always visible");
    }

    #[test]
    fn scan_wrapper_honours_the_fd_filter() {
        let sink = |_info: &Arc<ProcessInfo>, _entry: &FdEntry| {
            panic!("no entry may pass the rejecting filter");
        };
        let opts = ScanOptions::new()
            .no_sockets()
            .fd_filter(Arc::new(|_e: &FdEntry| false));
        scan(&opts, &sink).expect("scan must succeed");
    }
}
