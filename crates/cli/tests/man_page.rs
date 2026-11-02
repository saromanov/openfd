//! The committed `man/openfd.1` must match what `openfd-mangen` generates
//! from the current CLI definition. Regenerate with:
//!
//! ```sh
//! cargo run -p openfd --bin openfd-mangen -- man/openfd.1
//! ```

#[test]
fn committed_man_page_is_fresh() {
    let mut rendered = Vec::new();
    clap_mangen::Man::new(openfd::cli_command())
        .render(&mut rendered)
        .expect("render man page");
    let committed = include_bytes!("../../../man/openfd.1");
    assert_eq!(
        std::str::from_utf8(committed).unwrap(),
        std::str::from_utf8(&rendered).unwrap(),
        "man/openfd.1 is stale: regenerate with `cargo run -p openfd --bin openfd-mangen -- man/openfd.1`"
    );
}
