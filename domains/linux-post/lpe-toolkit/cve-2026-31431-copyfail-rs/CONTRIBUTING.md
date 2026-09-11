# Contributing

Private repo. Solo project for now.

## If access is granted to additional contributors

- Branch off `main`, PR back. No direct pushes.
- Match existing code style. No reformatting churn in feature PRs.
- Every offensive change must include the paired detection rule update under `detection/`. No exceptions, that's the project's reason to exist.
- Run `cargo fmt` + `cargo clippy --all-targets -- -D warnings` before pushing.
- Run `cargo test --release` before pushing.

## Commit hygiene

- Every commit on this repo uses date `2026-04-30T19:00:00+01:00` (project convention)
- Use `scripts/git-commit-1900.sh` wrapper, or set `GIT_AUTHOR_DATE` + `GIT_COMMITTER_DATE` env vars + `--date=`
- Author: `diemoeve <105520646+diemoeve@users.noreply.github.com>`
- No co-authored-by trailers
- Conventional Commits format encouraged (`feat:`, `fix:`, `docs:`, `chore:`)

## Build matrix

| Target | Why |
|--------|-----|
| `x86_64-unknown-linux-musl` | primary, dropper-shaped static binary |
| `aarch64-unknown-linux-musl` | ARM cloud + apple-silicon-via-emulation tests |

## Testing

| Layer | Tool |
|-------|------|
| Unit | `cargo test` |
| Integration (primitive correctness) | `cargo test --release` against /tmp test files |
| End-to-end exploit | manual on test VM (`scripts/vm-check.sh` first to confirm vuln status) |
| End-to-end detection | manual: snapshot baseline, run exploit, run detection, diff |

## Ethics

See `SECURITY.md`. Do not run exploit mode against systems you do not own.
