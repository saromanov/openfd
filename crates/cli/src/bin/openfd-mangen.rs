//! Generate the openfd man page: `openfd-mangen <output-path>`.

use std::path::PathBuf;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: openfd-mangen <output-path>");
            std::process::exit(2);
        }
    };
    let man = clap_mangen::Man::new(openfd::cli_command());
    let mut rendered = Vec::new();
    man.render(&mut rendered).expect("render man page");
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).expect("create man directory");
    }
    std::fs::write(&path, &rendered).unwrap_or_else(|e| {
        eprintln!("openfd-mangen: cannot write {}: {e}", path.display());
        std::process::exit(1);
    });
}
