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
    AddrFamily, Backend, FdEntry, FdKind, FdSink, ProcessInfo, ScanOptions, SockAddr, SockInfo,
    SockProto,
};

/// The backend for the current platform.
pub fn default_backend() -> Box<dyn Backend> {
    Box::new(scanner::ProcBackend::new())
}

/// Convenience wrapper: scan with [`default_backend`].
pub fn scan(opts: &ScanOptions, sink: &mut FdSink<'_>) -> std::io::Result<()> {
    default_backend().scan(opts, sink)
}
