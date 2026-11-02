<!-- One feature or fix per pull request. -->

## What

<!-- What does this PR change? -->

## Why

<!-- Link the issue: "Closes #123". -->

## Checklist

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --all --all-features --all-targets -- -D warnings` passes
- [ ] `cargo test --all` passes
- [ ] No `unsafe` added to `openfd-core`
- [ ] README updated if flags/behavior changed
- [ ] `man/openfd.1` regenerated if CLI flags changed:
      `cargo run -p openfd --bin openfd-mangen -- man/openfd.1`
