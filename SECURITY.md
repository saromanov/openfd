# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repository). Please do not open
a public issue for security reports.

Include: affected version (`openfd --version`), how to reproduce, expected vs
actual behavior.

## Scope notes

`openfd` is a read-only inspection tool:

- It reads `/proc` and `/etc/passwd` only.
- It opens no network sockets and performs no downloads.
- The core library (`openfd-core`) contains no `unsafe` code.
- It never elevates privileges and never writes outside its output.

Reports about misparsed `/proc` data that could cause wrong output or a panic
are in scope. Reports about issues that require an already-compromised system
are out of scope.
