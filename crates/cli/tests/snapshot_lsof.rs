//! Snapshot harness against the real `lsof`.
//!
//! Opt-in (needs `OPENFD_SNAPSHOT=1` and `lsof` on PATH): both tools race a
//! live system, so pid sets are compared with a churn tolerance instead of
//! strict equality. Run locally before releases:
//!
//! ```sh
//! OPENFD_SNAPSHOT=1 cargo test -p openfd --test snapshot_lsof -- --nocapture
//! ```

use std::collections::BTreeSet;
use std::process::Command;

#[test]
fn pid_set_matches_lsof_within_churn_tolerance() {
    if std::env::var("OPENFD_SNAPSHOT").as_deref() != Ok("1") {
        eprintln!("skipping: set OPENFD_SNAPSHOT=1 to run the lsof snapshot test");
        return;
    }
    let lsof = which_lsof().expect("lsof must be installed for the snapshot test");

    let our_pids = pid_set(env!("CARGO_BIN_EXE_openfd"), &["-t", "-n"]);
    let lsof_pids = pid_set(&lsof, &["-t", "-n"]);

    let ours_only: BTreeSet<u32> = our_pids.difference(&lsof_pids).copied().collect();
    let lsof_only: BTreeSet<u32> = lsof_pids.difference(&our_pids).copied().collect();

    eprintln!("pids only in openfd: {ours_only:?}");
    eprintln!("pids only in lsof:   {lsof_only:?}");

    // Processes spawn and exit between the two invocations; a few percent of
    // churn is normal on a desktop system.
    let base = lsof_pids.len().max(1) as f64;
    let diff = (ours_only.len() + lsof_only.len()) as f64;
    assert!(
        diff / base <= 0.10,
        "pid sets differ by more than 10%: openfd-only={ours_only:?} lsof-only={lsof_only:?}"
    );
}

fn pid_set(program: &str, args: &[&str]) -> BTreeSet<u32> {
    let out = Command::new(program)
        .args(args)
        .output()
        .expect("run program");
    assert!(
        out.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn which_lsof() -> Option<String> {
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        let p = dir.join("lsof");
        if p.is_file() {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}
