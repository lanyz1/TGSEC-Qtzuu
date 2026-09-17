# DIRTYFAIL — defender's playbook

A one-page operational guide for sysadmins assessing and mitigating
exposure to the Copy Fail and Dirty Frag CVE family on Linux hosts.

If you're operating a fleet of Linux servers, the questions below are
the ones to answer in order.

---

## 1. Am I vulnerable?

**Quickest answer (no compilation):**

```bash
curl -sSL https://raw.githubusercontent.com/KaraZajac/DIRTYFAIL/main/tools/dirtyfail-check.sh \
  | bash
```

(Read the script first if you don't trust me — it's ~150 lines of
plain bash, no curl-pipe-bash voodoo. Read-only on your system.)

Exit code: `0` mitigated, `1` vulnerable, `2` couldn't determine.

**Empirical answer (builds the C tool, runs the active probes):**

```bash
git clone https://github.com/KaraZajac/DIRTYFAIL.git
cd DIRTYFAIL && make
./dirtyfail --scan --active
```

The default `--scan` mode runs precondition checks (kernel version,
module presence, LSM state) plus an active probe of the Copy Fail
primitive against a sentinel file in `/tmp`. Adding `--active` extends
the sentinel-STORE probe to the other four primitives (ESP v4, ESP v6,
RxRPC, GCM) — this is the only way to distinguish a backported-patched
kernel from an unpatched one without running the full exploit. The
probes only modify temporary files in `/tmp`; `/etc/passwd` is never
touched.

**Per-CVE breakdown (manual checks):**

| Question | Command | Vulnerable if |
|---|---|---|
| Is the algif_aead module reachable? | `lsmod \| grep algif_aead` + `grep algif_aead /etc/modprobe.d/*` | Loaded AND not blacklisted |
| Are esp4/esp6 modules reachable? | `modinfo esp4 esp6` | Both present, not blacklisted |
| Is rxrpc reachable? | `lsmod \| grep rxrpc` + `getsockopt(AF_RXRPC, ...)` | Module loadable from unprivileged context |
| Is unprivileged userns hardened? | `cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns` | Returns `0` or file absent |
| Does PAM accept empty passwords? | `grep nullok /etc/pam.d/common-auth` | "nullok" present without "nullok_secure" |

---

## 2. How do I mitigate?

Three options, listed best-to-worst:

### A. Apply the upstream kernel patch (best)

The fix is mainline commit `f4c50a4034e6` (merged 2026-05-07). Each
distro's kernel package is on its own backport timeline:

| Distro | Status (as of 2026-05-09) |
|---|---|
| Debian 13 (`6.12.86+deb13`) | ✅ patched |
| Ubuntu 24.04 LTS | ❌ not yet patched (kernel 6.8.0-111) |
| Ubuntu 26.04 LTS | ❌ not yet patched (kernel 7.0.0-15.15, predates upstream merge) |
| AlmaLinux 10.1 | ❌ not yet patched (kernel 6.12 EL) |
| Fedora 44 | ❌ not yet patched (kernel 6.19.10) |

Run `apt list --upgradable linux-image-*` / `dnf check-update kernel`
periodically and apply.

### B. Layered LSM mitigation (Ubuntu 26.04 model)

If you're on Ubuntu 24.04 or 26.04, you can replicate Ubuntu 26.04's
defense-in-depth approach without waiting for the kernel patch:

```bash
# 1. Block unprivileged user namespaces from acquiring caps
echo 'kernel.apparmor_restrict_unprivileged_userns = 1' \
  | sudo tee /etc/sysctl.d/99-userns-restrict.conf
sudo sysctl --system

# 2. Verify the AA hardening is in effect:
sudo unshare -U -r bash -c 'echo deny > /proc/self/setgroups 2>&1' \
  || echo "OK: unprivileged userns has no caps (mitigation working)"
```

This blocks the EXPLOIT INFRASTRUCTURE (no caps in unprivileged
userns), not the underlying kernel bug. Real-root exploitation still
works.

### C. Module blacklist (`dirtyfail --mitigate` or manual)

Heaviest hammer — blacklists every module that hosts a primitive.
**Side effects: breaks IPsec, AFS, and any userspace using `AF_ALG`
AEAD.**

Automated:

```bash
sudo ./dirtyfail --mitigate
```

Manual equivalent:

```bash
sudo tee /etc/modprobe.d/dirtyfail-mitigations.conf <<'EOF'
install algif_aead /bin/false
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF

sudo rmmod algif_aead esp4 esp6 rxrpc 2>/dev/null
sudo sysctl vm.drop_caches=3
```

Undo: `sudo ./dirtyfail --cleanup-mitigate` (or delete the conf
files, then `sudo modprobe <name>` to reload as needed).

### D. Disable `pam_unix nullok`

Optional belt-and-suspenders: even if a page-cache STORE lands, the
exploit relies on PAM's `nullok` flag to convert "empty password
field in /etc/passwd" into a successful `su`. Removing `nullok` from
`/etc/pam.d/common-auth` (Debian/Ubuntu) or `/etc/pam.d/system-auth`
(Red Hat family) closes that step:

```bash
sudo sed -i 's/\bnullok\b//g' /etc/pam.d/common-auth   # Debian/Ubuntu
# Verify a passworded user can still log in normally before logging out!
```

---

## 3. What should I monitor?

Even after mitigation, the kernel bug remains until the patch lands.
For detection:

### auditd rules (universal)

A ready-to-load rules file ships in `tools/99-dirtyfail.rules`. It
covers six syscall paths used by the exploit chain: XFRM netlink,
add_key(rxrpc), unshare(CLONE_NEWUSER), AF_ALG socket creation,
AppArmor `change_onexec` writes, and direct `/etc/passwd`/`/etc/shadow`
modifications.

```bash
sudo install -m 0640 tools/99-dirtyfail.rules /etc/audit/rules.d/
sudo augenrules --load
sudo systemctl restart auditd
```

Search for events:

```bash
# grep is more reliable than ausearch on distros that use ENRICHED
# log_format (Debian 13, Fedora 44 — ausearch -k can return "no matches"
# even when SYSCALL events with the key are present in the file).
sudo grep -E 'type=SYSCALL.*key="dirtyfail-' /var/log/audit/audit.log | tail -20

# Or per-key, only the most recent entries:
sudo grep 'key="dirtyfail-xfrm"'    /var/log/audit/audit.log | tail -5
sudo grep 'key="dirtyfail-rxkey"'   /var/log/audit/audit.log | tail -5
sudo grep 'key="dirtyfail-userns"'  /var/log/audit/audit.log | tail -5
sudo grep 'key="dirtyfail-afalg"'   /var/log/audit/audit.log | tail -5
```

(`sudo ausearch -k <key>` is the documented tool for this and works on
older distros, but enriched-format compat issues mean `grep` is the
safer default.)

The `dirtyfail-userns` rule fires on every legitimate `unshare -U` and
rootless container start — pair it with `dirtyfail-xfrm` in a SIEM
correlation rule (same auid, both within ~5s) for a high-fidelity
alert. Tuning notes inline in the rules file.

### eBPF / falco (if you have it)

Falco's `Sensitive mount opened for writing` and `Detect outbound
connections to common miner pool ports` rule sets won't help directly,
but a custom rule on `unshare(CLONE_NEWUSER)` followed by
`sendto(SOCK_RAW, NETLINK_XFRM)` from a non-zero uid is high-fidelity.

### Cheap log signal

```bash
# Hits if our exploit's marker bytes show up in /etc/passwd's page cache
# (run periodically; doesn't catch every variant but is zero-cost)
grep -E '^[^:]+::0:0:|^[^:]+:x:0000:' /etc/passwd
```

---

## 4. Quick reference card

```
SCAN this host:
  curl ... | bash                     # bash check (no compile)
  ./dirtyfail --scan                  # preconds + Copy Fail probe (~1s)
  ./dirtyfail --scan --active         # all 5 sentinel-STORE probes (~10s)
  ./dirtyfail --scan --active --json  # same, machine-readable for SIEM

MITIGATE (Ubuntu / fleet-wide):
  sudo ./dirtyfail --mitigate         # one-shot defensive deployment
  sudo ./dirtyfail --cleanup-mitigate # undo

MITIGATE (manual, no DIRTYFAIL):
  See section 2-C above.

PATCH:
  apt list --upgradable | grep linux-image
  dnf check-update kernel

MONITOR:
  /etc/audit/rules.d/99-dirtyfail.rules     (see section 3)

EMERGENCY (suspected compromise via this CVE class):
  sudo sysctl vm.drop_caches=3              # evicts page-cache exploits
  sudo systemctl restart sshd               # forces re-read of /etc/passwd
  grep dirtyfail /etc/passwd                # check for backdoor user
  rm -f /var/tmp/.dirtyfail.state           # clean DIRTYFAIL state file
```

---

## 5. Glossary

- **Page-cache write**: kernel writes attacker-controlled bytes into the
  in-memory copy of a file (`/etc/passwd`, `/usr/bin/su`) without
  modifying the file on disk. Persists in RAM until eviction.
- **PAM nullok**: configuration flag that permits authentication for
  accounts with an empty password field in `/etc/passwd` (or
  `/etc/shadow`).
- **xfrm-ESP**: the kernel's ESP (Encapsulating Security Payload)
  implementation in the IPsec stack. The bug class affects in-place
  AEAD decrypt over splice-pinned page-cache pages.
- **Userns capability stripping**: kernel-level enforcement that
  unprivileged user namespaces have no `CAP_NET_ADMIN` /
  `CAP_SYS_ADMIN`, blocking exploit infrastructure even when the
  underlying kernel bug is unpatched.
