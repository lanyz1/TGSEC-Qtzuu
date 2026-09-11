# copyfail-rs v0.1.0

First public release. Multi-vector PoC + paired detection for **CVE-2026-31431** (CopyFail).

Single static `no_std` Rust binary. ~108 KB stripped musl on x86_64.

## What ships

### Exploit (`--mode exploit`)

- `pam` (NEW, first public PoC for this surface): single 4-byte killshot on `/etc/pam.d/common-auth` (Debian/Ubuntu) or `system-auth` (Fedora/RHEL/Arch). Comments out `pam_deny.so` so the auth chain falls through `pam_unix` → `pam_permit.so`. Sudo with any password = root.
- `su`: setuid binary text-section mutation in `/usr/bin/su`. `execve()` runs operator-supplied shellcode as root.
- `passwd`: UID flip in `/etc/passwd`. Subsequent `su <user>` or login = root.
- `--vector auto` (default): ranks `pam > su > passwd` by stealth, picks the highest applicable.
- `--vector all`: tries each vector in turn until one succeeds.
- `--vector list`, `--dry-run`, `--strict`, `--json`, `--no-shell`, `--target USER`, `--shell PATH`.
- PTY drop: on PAM/auto success, the binary forks a `/dev/ptmx` pair, execs `sudo -k -S -i`, feeds it any password, and relays the resulting root shell to the operator's terminal. One command, one root shell.

### Detection (`--mode detect`)

- `--check`: kernel + `algif_aead` module + `authencesn` template + `CONFIG_CRYPTO_USER_API_AEAD` (=y vs =m) + modprobe blacklist. Verdict: VULNERABLE / MITIGATED / NOT_EXPLOITABLE / UNKNOWN.
- `--scan`: cache-vs-disk hash diff via O_DIRECT (filesystem-aware: ext4/xfs/btrfs use O_DIRECT, overlayfs falls back to `posix_fadvise(DONTNEED)`, tmpfs skipped).
- `--baseline FILE` / `--diff FILE`: snapshot known-clean state, diff later. Cache-only deltas surface as `[CACHE-ONLY (CopyFail signature)]`.
- `--watch [--interval N]`: daemon mode with periodic scan.
- `--hunt --hosts FILE`: SSH fleet sweep with JSON aggregation.
- `--json` everywhere for SIEM ingest.

This is the **only public tool that catches CopyFail tampering**. Mainstream FIM (AIDE, Wazuh, OSSEC, Tripwire, Samhain) is structurally blind: they read via buffered I/O, get cache-served bytes, hash those as truth.

### Detection artifacts (`detection/`)

- `sigma/copyfail-af-alg.yml`, Sigma rule, AF_ALG SOCK_SEQPACKET creation by non-root.
- `auditd/copyfail.rules`, auditd ruleset, key `copyfail_afalg_socket`.
- `ebpf/copyfail-trace.bt`, bpftrace one-liner.
- `apparmor/copyfail-block.profile`, AppArmor 3.0+ deny rule.
- `mitigation/disable-algif.sh`, modprobe blacklist + `=y` warning.

## Pre-built binaries

Three musl-static, fully self-contained binaries attached to this release. SHA256 sums in `checksums.txt`.

| Asset | Target | Size |
|-------|--------|------|
| `copyfail-x86_64-musl` | x86_64-unknown-linux-musl | 108 KB |
| `copyfail-aarch64-musl` | aarch64-unknown-linux-musl | 96 KB |
| `copyfail-armv7-musleabihf` | armv7-unknown-linux-musleabihf | 86 KB |
| `checksums.txt` | sha256 sums |, |

## Verification

```
$ sha256sum -c checksums.txt
copyfail-x86_64-musl: OK
copyfail-aarch64-musl: OK
copyfail-armv7-musleabihf: OK
```

## Documentation

- [`README.md`](../blob/main/README.md), top-level, terse.
- [`BLOG.md`](../blob/main/BLOG.md), long-form narrative version.
- [`docs/usage.md`](../blob/main/docs/usage.md), concrete examples per mode.
- [`docs/threat-model.md`](../blob/main/docs/threat-model.md), STRIDE-flavored, ~1 page.
- [`docs/PUBLISH-CHECKLIST.md`](../blob/main/docs/PUBLISH-CHECKLIST.md), maintainer checklist.

## Credits

| Contribution | Who |
|--------------|-----|
| Bug discovery + CVE coordination | Theori / Xint (disclosed 2026-04-29) |
| Original Python PoC | Theori / Xint |
| C port + 2-vector taxonomy + nolibc packaging | tgies, `github.com/tgies/copy-fail-c` |
| Static Go port | badsectorlabs, `github.com/badsectorlabs/copyfail-go` |
| **Rust port + PAM vector + dual-mode detection** | **diemoeve (this project)** |

## License

MIT.

## Authorization & ethics

Run only on hardware you own or have written authorization to test. Detection mode (`--mode detect`) is read-only and safe on production. Exploit mode mutates the kernel page cache; treat as destructive.
