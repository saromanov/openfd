# Contributing

Thanks for considering a contribution.

## Ground rules

- Rust stable; the workspace uses edition 2024 (`rust-version = 1.85`).
- `cargo fmt`, `cargo clippy --all --all-features --all-targets -- -D warnings`
  and `cargo test --all` must pass. CI enforces all three.
- No `unsafe` in `openfd-core`. If a change seems to need it, open an issue first.
- One feature per pull request.

## Good first contributions

See issues labeled `good first issue`. Roadmap-level items (netlink socket
resolution, `--watch`, `--top`) are specified in the README/issue tracker.

## Commit messages

Conventional, imperative, in English: `feat: add --summary`, `fix: handle
exited processes during scan`, `docs: ...`, `ci: ...`.

## Testing

- Unit tests live next to the code (`#[cfg(test)]`).
- `/proc` integration tests scan the test process itself — keep them
  hermetic (temp files via `tempfile`, no network, no other-user assumptions).
- The lsof snapshot harness is opt-in:
  `OPENFD_SNAPSHOT=1 cargo test -p openfd --test snapshot_lsof`.
