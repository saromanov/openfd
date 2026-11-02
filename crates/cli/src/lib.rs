//! Library surface of the openfd CLI crate: argument definitions, filters,
//! output printers and colors. Shared by the `openfd` binary, the
//! `openfd-mangen` generator and integration tests.

pub mod args;
pub mod color;
pub mod filters;
pub mod output;

pub use args::{Args, cli_command};
