# CVE-2026-31431 ("Copy Fail") Toolkit

Detector and proof-of-concept LPE for the Linux `algif_aead` /
`authencesn` page-cache scratch-write bug disclosed 2026-04-29.

Disclosure writeup: <https://xint.io/blog/copy-fail-linux-distributions>

## Authorization

Use only on hosts you own or are explicitly engaged to assess. The LPE
modifies in-memory state (page cache) but the technique is real
privilege escalation — running it on systems without authorization is
illegal in most jurisdictions.

## Vulnerability summary

`algif_aead` runs AEAD operations in-place (`req->src == req->dst`).
When the source data is fed in via `splice()` from a regular file, the
destination scatterlist contains references to the file's page-cache
pages — i.e. the kernel will write into them. The
`authencesn(hmac(sha256), cbc(aes))` algorithm then performs a 4-byte
"scratch" write of the AAD's `seqno_lo` field (bytes 4–7 of the
sendmsg-supplied AAD) into that destination, corrupting the page-cache
copy of the file.

Because the on-disk file is never modified, there is no on-disk
signature; the corruption is observed only by readers that share the
page cache. `/etc/passwd` and `/usr/bin/su` are both world-readable, so
an unprivileged local user can corrupt the running kernel's view of
either.

Affected: kernels carrying commit `72548b093ee3` (in-place AEAD, 2017)
without the upstream revert. The disclosure confirmed Ubuntu 24.04 LTS,
Amazon Linux 2023, RHEL 14.3, and SUSE 16, but the underlying primitive
predates that range.

## Files

| File | Purpose |
| --- | --- |
| `test_cve_2026_31431.py` | Non-destructive detector. Operates on a sentinel file in a temp dir; never touches system binaries. |
| `exploit_cve_2026_31431.py` | LPE. Flips the running user's UID to 0 in `/etc/passwd`'s page cache, then invokes `su` for a root shell. |

Both scripts are pure Python 3.10+ stdlib.

## Quick start

```sh
# 1. Detect
python3 test_cve_2026_31431.py
#   exit 0 = not vulnerable, 2 = vulnerable, 1 = test error

# 2. Exploit (interactive — su will prompt for your own password)
python3 exploit_cve_2026_31431.py --shell
```

## Detector usage

```
python3 test_cve_2026_31431.py
```

What it does:

1. Confirms `AF_ALG` and the `authencesn(hmac(sha256),cbc(aes))`
   algorithm are reachable from an unprivileged process.
2. Creates a 4 KiB sentinel file in a temp directory, populates the
   page cache.
3. Sends 8 bytes of AAD inline via `sendmsg`+cmsg with seqno_lo set to
   the marker `PWND`, then `os.splice()`s 32 bytes of the sentinel's
   page-cache page into the AF_ALG op socket.
4. Calls `recv()` to drive decryption. The auth check fails with
   `EBADMSG`; the scratch write fires regardless.
5. Re-reads the file (page cache, not disk) and looks for the marker.

Output classes:

- `Precondition not met` — `AF_ALG` or `authencesn` unavailable. Exit 0.
- `VULNERABLE to CVE-2026-31431` — marker `PWND` landed in the spliced
  page. Exit 2.
- `Page cache MODIFIED via in-place AEAD splice path` — the page was
  written to but the marker did not land at the expected position.
  Treat as vulnerable. Exit 2.
- `Page cache intact` — patched. Exit 0.

The detector never touches `/usr/bin/su`, `/etc/passwd`, or any other
file outside the temp directory it creates, and that file is removed on
exit.

## LPE usage

```
python3 exploit_cve_2026_31431.py            # patch only, print next steps
python3 exploit_cve_2026_31431.py --shell    # patch and exec `su <user>`
```

What it does:

1. Looks up the running user's UID line in `/etc/passwd` and finds the
   byte offset of the 4-character UID field.
2. Issues one `write4` against that offset, replacing the UID with
   `0000`.
3. Calls `pwd.getpwnam(user)` to confirm libc now reports UID 0.
4. With `--shell`, `execvp("su", ["su", user])`. Enter your own
   password. PAM validates against `/etc/shadow` (untouched), then
   `setuid(getpwnam(user).pw_uid)` lands at 0.

### Requirements

- Running user has a 4-digit UID (1000–9999). 1- to 3-digit UIDs
  require multi-shot writes — extend `write4` accordingly.
- No NSS caching daemon (`nscd`, `sssd`, `systemd-userdbd`) is masking
  `/etc/passwd` reads. If `getpwnam` still returns the real UID after
  the patch, restart or bypass the cache, or pick a different user.
- `/etc/passwd` page must remain in cache between the patch and the
  `su` exec. In practice this is reliable on any system with normal
  memory pressure.

### Reverting

The on-disk `/etc/passwd` is unchanged.

**Dry-run** (`exploit_cve_2026_31431.py` without `--shell`) auto-evicts
the corrupted page on exit via `POSIX_FADV_DONTNEED`, so UID→name
lookups go back to normal immediately.

**After `--shell`**, the page is left corrupted until you clear it.
While it is corrupted, anything resolving UID 1000 → name (e.g. `ls`,
file managers, scp/sftp ownership checks) will fail or show numeric
IDs. To clear:

```sh
# unprivileged - request page-cache eviction for /etc/passwd:
python3 -c "import os; fd=os.open('/etc/passwd', os.O_RDONLY); \
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED); os.close(fd)"

# from the root shell:
echo 3 > /proc/sys/vm/drop_caches
```

A reboot also clears it.

## How `write4` works

```
sendmsg([8-byte AAD], cmsg=[ALG_SET_OP=DECRYPT, ALG_SET_IV, ALG_SET_AEAD_ASSOCLEN=8],
        flags=MSG_MORE)
splice(target_fd, pipe_w, 32, offset_src=file_offset)
splice(pipe_r, op_fd, 32)
recv(op_fd)   # EBADMSG; scratch write has already landed
```

The 4 bytes from AAD positions 4–7 (`seqno_lo`) are written by
`authencesn` into the destination scatterlist, which on this code path
is the page-cache page we spliced from `target_fd`. The landing offset
within the page corresponds to the `offset_src` we passed to `splice()`.

## Mitigation

Until the patched kernel reaches your distro:

```sh
sudo tee /etc/modprobe.d/disable-algif-aead.conf <<<'install algif_aead /bin/false'
sudo rmmod algif_aead 2>/dev/null
```

After applying, `test_cve_2026_31431.py` should report `Precondition
not met` and exit 0.

The upstream fix reverts in-place AEAD operations to out-of-place,
keeping page-cache pages out of writable scatterlists.

## References

- Xint disclosure writeup: <https://xint.io/blog/copy-fail-linux-distributions>
- CVE-2026-31431
