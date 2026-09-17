# NOTICE

## fcrypt S-box constants and key schedule

`src/fcrypt.c` contains the four 256-byte S-box tables `SBOX0_RAW`,
`SBOX1_RAW`, `SBOX2_RAW`, and `SBOX3_RAW`, along with the 56-bit key
packing and 11-bit-rotation key schedule for the rxkad fcrypt cipher.

These tables and the key schedule are **protocol constants** of the
Andrew File System (AFS) rxkad authentication scheme. They appear
verbatim in:

- The Linux kernel's `crypto/fcrypt.c` (GPL-2.0,
  Copyright © David Howells / KTH)
- IBM's open-source AFS distribution
- OpenAFS upstream
- Heimdal Kerberos (rxkad implementation)

Cryptographic constants required by a wire protocol are facts about
the protocol, not creative expression — using them is what makes
interoperability with the Linux kernel possible. We list this here for
transparency: while the S-box bytes are identical to the kernel's
table, the rest of `src/fcrypt.c` (table preprocessing, brute-force
harness, predicates, splitmix64 search) is independently written
DIRTYFAIL code under the project's MIT license.

If you intend to redistribute DIRTYFAIL in a context where strict
license compatibility matters, treat `src/fcrypt.c` as carrying the
same license obligations as the kernel `crypto/fcrypt.c` source for
the S-box constants alone.

## Reference exploits

The detection and exploit techniques in DIRTYFAIL were studied from:

- [Smarttfoxx/copyfail](https://github.com/Smarttfoxx/copyfail) — Copy
  Fail original C PoC
- [rootsecdev/cve_2026_31431](https://github.com/rootsecdev/cve_2026_31431)
  — Copy Fail Python detector + UID-flip exploit
- [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) — Dirty Frag
  full chain PoC by Hyunwoo Kim ([@v4bel](https://x.com/v4bel))

DIRTYFAIL implementations are independently written in C, organized
around a single binary with detection-first defaults, but the protocol
mechanics (XFRM SA layout, RxRPC handshake forgery, rxkad checksum
formula) are necessarily identical to the upstream PoCs because they
target the same kernel interfaces.

## Additional techniques from 0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo

The following DIRTYFAIL features draw on techniques first published by
[0xdeadbeefnetwork](https://github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo):

- `src/copyfail_gcm.c` — `rfc4106(gcm(aes))` AEAD in xfrm-ESP, using
  AES-GCM keystream brute-force to land a single byte at an arbitrary
  file offset. Reimplemented in DIRTYFAIL style using AF_ALG instead
  of OpenSSL EVP, eliminating the `libssl-dev` runtime dependency.
- `src/dirtyfrag_esp6.c` — IPv6 dual of xfrm-ESP. cf2 demonstrated the
  esp6 size-gate workaround (≥48-byte frame); we reproduce that with
  an 8-byte vmsplice'd pad.
- `src/apparmor_bypass.c` — the `change_onexec(crun)` →
  `change_onexec(chrome)` → unshare re-exec dance to escape Ubuntu's
  unprivileged-userns AppArmor restriction. cf2 credits the technique
  to Brad Spengler (grsecurity); we expose it as a `--aa-bypass` flag
  and auto-arm it when a restrictive profile is detected.
- `src/backdoor.c` — length-matched overwrite of a `nologin` line in
  /etc/passwd with `dirtyfail::0:0:<pad>:/:/bin/bash`. cf2 publishes
  the shell-script harness (and uses the username `sick`); DIRTYFAIL
  ports it into a single C function driving our 1-byte primitive,
  with the username matched to this project for easy auditing.

See [README §11 — Credits](README.md#11-credits) for the full list.
