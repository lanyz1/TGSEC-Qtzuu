# copyfail-rs

> Multi-vector PoC + paired detection for CVE-2026-31431 (CopyFail).
> Includes a novel PAM auth-bypass vector that no other public PoC ships.
> Detection mode catches what AIDE / Wazuh / OSSEC / Tripwire structurally cannot.

## TL;DR

CopyFail (CVE-2026-31431) lets an unprivileged user mutate any file they can read inside the Linux page cache. The mutated bytes are what subsequent reads (including `execve()` of setuid binaries and PAM config parsing) see. The on-disk file stays clean, so every mainstream FIM tool that reads via buffered I/O hashes the corrupted bytes as truth and reports "no change."

This repo ships:
- A working PoC with **three vectors**: `su` (binary mutation), `passwd` (UID flip), and a novel `pam` (auth-chain killshot, first public).
- A **detection mode** that uses `O_DIRECT` to bypass the page cache and compare disk vs cache hashes, the only public tool that catches CopyFail tampering reliably.
- Sigma rules, auditd rules, an eBPF tracing one-liner, an AppArmor profile, and a tested mitigation script.

Single static `no_std` Rust binary. ~85 KB stripped musl. Runs anywhere Linux.

## The two-line headline

```
$ copyfail-rs --mode detect --diff /etc/pam.d/common-auth
[CACHE-ONLY (CopyFail signature)] /etc/pam.d/common-auth
  current_disk:  117dab1c... (UNCHANGED, what AIDE / Wazuh / Tripwire see)
  current_cache: 23c4f1ee... (CHANGED , the actual loaded code)
```

The disk hash and the cache hash diverging is the CopyFail fingerprint. No other public tool surfaces this.

## Quick demo (vulnerable Linux host)

```
# Exploit (PAM vector, lands in root shell):
$ copyfail-rs --mode exploit
[sudo] password for noot: root@host:~#

# Detection (catches the tampering):
$ copyfail-rs --mode detect --scan
TAMPERED (1):
  /etc/pam.d/common-auth [ext4]
    cache:  23c4f1ee...
    disk:   117dab1c...

# Mitigate:
$ copyfail-rs --mode detect --check
verdict: vulnerable
$ echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf
$ sudo rmmod algif_aead
$ copyfail-rs --mode detect --check
verdict: mitigated
```

## Why this exists

CopyFail was disclosed 2026-04-29 by Theori / Xint. Within hours, three public PoCs landed: a Python one-liner from Theori, a portable C port by tgies, a static Go port by badsectorlabs. All three target either `/usr/bin/su` (binary mutation) or `/etc/passwd` (UID flip). All three are offense-only.

That left two gaps:

1. **No public detection tool.** Defenders running incident response on a suspected CopyFail hit had nothing off-the-shelf. The mainstream FIM stack (AIDE, Wazuh, OSSEC, Tripwire, Samhain) is structurally blind to page-cache mutation: they all read via buffered I/O, get cache-served bytes, and hash those as truth. After cache eviction the disk version is what they see, clean. Result: a successful CopyFail exploitation is invisible to the file integrity monitor sitting next to it.

2. **No public PAM vector.** PAM config files (`/etc/pam.d/common-auth` on Debian/Ubuntu, `/etc/pam.d/system-auth` on Fedora/RHEL/Arch) are the auth-policy substrate for `sudo`, `su`, `login`, and friends. PAM uses plain `fopen()` to read its config on every authentication attempt, page cache served. Mutating four bytes turns the auth chain from password-required into password-bypassed.

This project closes both gaps in a single static binary.

## Vectors (offense)

| Vector | Target | Effect | Notes |
|--------|--------|--------|-------|
| `su` | `/usr/bin/su` | Mutates setuid binary's text section in cache; `execve()` runs operator-supplied shellcode as root | Mirrors tgies / badsectorlabs / theori-io |
| `passwd` | `/etc/passwd` | Flips target user's UID field to `0000`; subsequent `su <user>` or new login = root | Side effect: breaks SSH for that user (sshd NSS sees uid=0, expects keys at /root/.ssh) |
| `pam` | `/etc/pam.d/common-auth` (Debian/Ubuntu) or `system-auth` (Fedora/RHEL/Arch) | Single 4-byte killshot: replaces `auth requisite pam_deny.so` with `#aut requisite pam_deny.so` (commented out). Auth chain falls through `pam_unix` → `pam_permit.so` → SUCCESS regardless of password. | First public PoC for this surface. Alpine n/a (sudo built `--without-pam`) |

Auto-selection: `--vector auto` ranks by stealth+confidence (pam > su > passwd) and picks the highest applicable for the host. Fallback chain: `--vector all` tries each in order.

## Detection (defense)

| Mode | What it does |
|------|--------------|
| `--check` | Static diagnostic: kernel version, module loaded, template registered, `/boot/config-*` for `CONFIG_CRYPTO_USER_API_AEAD` (=y silently bypasses modprobe mitigation), modprobe blacklist present. Verdict: vulnerable / mitigated / not-exploitable. |
| `--scan [PATH ...]` | Cache-vs-disk hash diff on critical files. `O_DIRECT` for ext4/xfs/btrfs (disk read), buffered for cache. `statfs()`-branched: overlayfs falls back to `posix_fadvise(POSIX_FADV_DONTNEED)`; tmpfs has no on-disk view, skipped. |
| `--baseline FILE` / `--diff FILE` | Snapshot known-clean state, diff against current state. Reveals "cache-only" deltas, files where disk matches baseline but cache differs (the CopyFail fingerprint). |
| `--watch [--interval N]` | Daemon mode. Periodic scan loop. SIGTERM clean shutdown. |
| `--hunt --hosts FILE` | Fleet sweep via `ssh` subprocess. JSON aggregation across hosts. |

All output supports `--json` for SIEM ingest / pipeline use.

## Detection artifacts (`detection/`)

Live alongside the binary, per the purple-team practice:

- `sigma/copyfail-af-alg.yml`, Sigma rule for AF_ALG aead socket creation by non-root processes. Drop into your SIEM.
- `auditd/copyfail.rules`, auditd ruleset. Load with `augenrules --load`.
- `ebpf/copyfail-trace.bt`, bpftrace one-liner. Live tracing during incident response.
- `apparmor/copyfail-block.profile`, AppArmor 3.0+ profile. Denies AF_ALG sockets for confined unprivileged processes.
- `mitigation/disable-algif.sh`, Modprobe blacklist application script with the `CONFIG_=y` warning bake in.

## Why FIM tools miss this

Every public FIM works the same way: `open()`, `read()`, hash bytes, compare against baseline. That `read()` goes through the kernel's page cache. After CopyFail mutation, the page cache holds the corrupted bytes. The FIM hashes those corrupted bytes. Either:

- **Real-time monitoring (inotify, auditd `-w`, fanotify):** never fires. CopyFail mutation doesn't go through the VFS write path. The page never gets marked dirty. No event emitted.
- **Periodic rescan (AIDE, Wazuh syscheck):** races cache eviction. If the cache evicted between exploit and scan, the rescan reads disk → sees clean → reports "no change." If the cache is still hot, the rescan reads the corrupted bytes → hashes match the modification, but the exploit has already done its work.

The fix isn't config tuning. It's a different read path. `O_DIRECT` bypasses the page cache and goes to disk. Compare the two hashes. Mismatch = CopyFail signature. That's what `--scan` does.

## Mitigation

The two-line modprobe blacklist defeats all techniques (when `CONFIG_CRYPTO_USER_API_AEAD=m`, which is the common case):

```
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf
sudo rmmod algif_aead
```

Or upgrade to a kernel including mainline commit `a664bf3d603d` (April 2026). As of disclosure date, only Debian Sid/Forky shipped a backport. Ubuntu LTS, RHEL 8/9/10, SUSE 15/16, Amazon Linux 2/2023, Fedora 40/41/42, Arch, Oracle, all confirmed vulnerable, no fixed package available.

Caveat (R3 finding): if `CONFIG_CRYPTO_USER_API_AEAD=y` (built-in), the modprobe blacklist is silently ineffective, the module is already part of the kernel image. Verify with `grep CONFIG_CRYPTO_USER_API_AEAD /boot/config-$(uname -r)`. If `=y`, the only mitigation is a kernel rebuild as `=m` or seccomp/AppArmor blocking AF_ALG.

Important operational note: applying the mitigation after exploitation does not undo past mutations. The killshot persists in RAM until cache eviction or reboot. Assume reboot is required for full restoration.

## Build

```bash
cargo build --release --target x86_64-unknown-linux-musl
# or aarch64-unknown-linux-musl, armv7-unknown-linux-musleabihf
```

Stripped binary sizes:

| Target | Size |
|--------|------|
| x86_64-unknown-linux-musl | ~85 KB |
| aarch64-unknown-linux-musl | ~70 KB |
| armv7-unknown-linux-musleabihf | ~75 KB |

`no_std`, no allocator, no runtime dependencies. Single static binary.

## Authorization & ethics

- Run only on hardware you own or have written authorization to test.
- Detection mode (`--mode detect`) is read-only and safe on production hosts.
- Exploit mode (`--mode exploit`) modifies the kernel page cache. Even though the modification is RAM-only, treat it as destructive, it bypasses authentication for any subsequent caller.
- This repo exists because CVE-2026-31431 is publicly disclosed and defenders need detection tooling that mainstream FIM cannot provide. It does not extend the disclosure surface, it implements detection and reproduction tooling for an already-public bug, plus a novel exploitation vector for the same bug to demonstrate the detection's coverage.

## Credits

| Contribution | Who |
|--------------|-----|
| Bug discovery + CVE coordination | Theori / Xint (disclosed 2026-04-29) |
| Original Python PoC | Theori / Xint |
| C port + 2-vector taxonomy + nolibc packaging | tgies, `github.com/tgies/copy-fail-c` |
| Static Go port | badsectorlabs, `github.com/badsectorlabs/copyfail-go` |
| **Rust port + PAM vector + dual-mode detection** | **diemoeve (this project)** |

## License

MIT. See `LICENSE`.

## References

- Disclosure: https://copy.fail/
- Mainline fix: Linux commit `a664bf3d603d` (April 2026)
- Floor commit: `72548b093ee3` (August 2017, kernel 4.14, introduced the AF_ALG iov_iter rework that the bug exploits)
- Structural analog: Dirty Pipe (CVE-2022-0847), same splice + page-cache mechanism, different trigger
