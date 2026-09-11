# copyfail-rs, threat model

Dual-mode tool. STRIDE-flavored, ~1 page.

## What this binary is

A single static `no_std` musl Rust binary implementing CVE-2026-31431 (CopyFail) on the offense side and a paired O_DIRECT-vs-cache hash-diff detector on the defense side. Vulnerability is in the upstream Linux kernel's AF_ALG/`algif_aead` + splice path. This binary is one of multiple public PoCs (Theori Python, tgies C, badsectorlabs Go) for the same kernel bug; the differentiator is the novel PAM vector and the detection mode.

## Who can use it

| Actor | Can do | Cannot do |
|-------|--------|-----------|
| Local unprivileged user on a vulnerable kernel | Run `--mode exploit` to get a root shell on **this same host** | Pivot off-host, escalate cross-host, persist past reboot |
| Remote operator with SSH | Use `--mode detect --hunt --hosts FILE` to fan out scans across own fleet | Exploit a remote host (the binary cannot exploit over the network; it must be executed on the target) |
| Defender / SOC analyst | Run `--mode detect` (read-only) on production to find CopyFail tampering | Block a live exploit in flight (detection is post-fact; for prevention, apply the modprobe blacklist) |

This is a local privilege-escalation primitive plus a host-local forensic detector. Network attack surface is zero.

## What the binary does on each invocation

### `--mode exploit --vector <pam|su|passwd>`

1. Probes kernel: `/proc/modules`, `/proc/crypto`, applicable() per vector.
2. Opens AF_ALG socket (`socket(AF_ALG, SOCK_SEQPACKET, 0)` + bind to `algif_aead`/`authencesn`).
3. Constructs in-place encrypt operation with crafted AAD/payload geometry; `splice()` from a pipe into the AF_ALG op socket targeting the page-cache pages of the victim file (`/etc/pam.d/common-auth`, `/usr/bin/su`, or `/etc/passwd`).
4. Mutates the cached page bytes. **Disk file is never written.**
5. PAM/su vector: drops a TTY into root via `sudo -k -S -i` driven by a forked PTY (`/dev/ptmx` + `grantpt` + `unlockpt` + `setsid` + `TIOCSCTTY` + `dup2` + `execv`).

### `--mode detect`

- `--check`: reads `/proc/version`, `/proc/modules`, `/proc/crypto`, `/boot/config-$(uname -r)` (streaming grep), `/etc/modprobe.d/`. Returns verdict.
- `--scan` / `--diff`: opens each target file twice, once with `O_DIRECT` (skip cache) when the filesystem supports it, once with normal `read()` (cache-served), hashes both with sha256, compares.
- `--baseline`: dumps a JSON of `(path, disk_hash, statfs_fstype)` snapshots.
- `--watch`: re-runs scan loop with `nanosleep`. SIGTERM closes cleanly.
- `--hunt`: forks `ssh` to each host in `--hosts FILE` and runs `--mode detect --check --json` over the link.

## What persists after the binary exits

| Mode | Persistent state |
|------|------------------|
| Exploit | **Page-cache mutation** on the target file. Persists until the kernel evicts the page (memory pressure, `echo 3 > /proc/sys/vm/drop_caches`, or reboot). Disk file is byte-identical to before the run. PAM bypass remains active for any subsequent caller (sudo / login / su) until eviction. |
| Detect | None. All file opens are read-only. `--baseline` writes a JSON file at the path you specify; nothing else writes. |
| `--watch` | None (process state only). SIGTERM-clean. |
| `--hunt` | Outbound ssh connections during the run. No client-side state once the process exits. |

## What the detection mode reveals

- Cache-vs-disk hash divergence on monitored files: the **CopyFail signature**. Every public PoC at the time of writing leaves this signature.
- Kernel/module/template state for vulnerability assessment.
- Which filesystems on the host don't support O_DIRECT (overlayfs, tmpfs, fuse), useful for detection-coverage gap analysis.
- The full set of paths checked. No per-file content is logged, only hashes (sha256, 32 bytes each, attacker can't reconstruct contents from hash).

## What is intentionally NOT in scope

This binary **does not** implement:

- Post-exploit persistence (no rootkit, no cron, no systemd unit, no SSH key drop, no /etc/passwd write, only RAM-only mutation).
- C2, beaconing, exfiltration, or any network callback.
- Lateral movement (no SSH client outside `--hunt`, which is read-only check; no SMB, no Kerberos, no WMI equivalent).
- Detection-evasion against EDR / AV / kernel-hardening (no syscall obfuscation, no anti-debug, no bootkit). The Sigma + auditd + eBPF rules in `detection/` are designed to detect *this exact binary*.
- Multi-host exploitation. Each `--mode exploit` run is a single-host operation. `--hunt` is detect-only.
- Non-Linux targets. AF_ALG is Linux-specific.
- Vector against `/etc/shadow` or sudoers configurations (deferred / out-of-scope per project spec).

## STRIDE on the binary itself

| Threat | Surface | Mitigation |
|--------|---------|-----------|
| Spoofing | Operator runs the wrong build (e.g., a tampered binary attacking unintended files). | SHA256 sums attached to GitHub release; all builds are reproducible-ish (`cargo build --release --target *-musl` with a pinned Cargo.lock). |
| Tampering with the binary | Distribution channel (GitHub release attachment). | Private repo; signed-tag practice; sums posted alongside binaries. |
| Repudiation | Operator runs `--mode exploit` and denies it. | auditd rule (`detection/auditd/copyfail.rules`) catches the AF_ALG SOCK_SEQPACKET socket creation. Sigma rule covers the same in SIEM. |
| Information disclosure | Detect mode logs paths or hashes the operator considers sensitive. | All output is opt-in stdout / `--json`. `--watch` writes to stderr only (no syslog backend in v1). |
| Denial of service | Repeated `--mode exploit` against PAM config bricks auth on the host. | Idempotent (S2.7), second run is a no-op when the bypass is already active. PAM bypass is *unlock*, not lock; sudo continues to accept any string, so no DoS arises from the exploit itself. The page-cache mutation does, however, block the *original* user's correct password on `getpwnam` callers if cache served (see passwd vector caveat in S2 findings). |
| Elevation of privilege | The whole point. | Mitigation: modprobe blacklist (`detection/mitigation/disable-algif.sh`) + kernel patch backport. Detection: `--mode detect`. AppArmor profile (`detection/apparmor/copyfail-block.profile`) deny-rules `network alg` for confined unprivileged processes, defense-in-depth. |

## Trust boundaries

- `--mode exploit` requires **local execution** on the target. There is no network ingress. Trust boundary is the host kernel; the binary trusts it not to lie about `/proc/modules` etc. and operates within the user's existing UID's capability set up to the moment of exploitation.
- `--mode detect --hunt` shells out to `ssh`. SSH host-key trust is the operator's responsibility (`~/.ssh/known_hosts`). The binary does not bypass or modify ssh-agent / `StrictHostKeyChecking`.
- Output is the operator's responsibility to handle (don't `--json | tee` to a world-readable file in a multi-tenant environment).
