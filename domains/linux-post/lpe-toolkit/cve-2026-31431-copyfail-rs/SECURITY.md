# Security Policy

## Scope

This is a research project for detection engineering and purple team
training. Code in this repository targets CVE-2026-31431 (CopyFail), a
publicly disclosed Linux kernel vulnerability.

## Responsible use

- Run only on hardware you own or have written authorization to test
- Do not deploy against systems without permission
- Detection mode (`--mode detect`) is read-only and safe to run on
  production hosts; exploit mode (`--mode exploit`) modifies kernel page
  cache and is destructive in spirit even if RAM-only

## Reporting

This repo is private. If access is granted to additional collaborators
who find issues, raise an issue on the repository.

## Disclosure status

CVE-2026-31431 is publicly disclosed (2026-04-29 by Theori / Xint).
This project does not extend the disclosure surface, it implements
detection and reproduction tooling for an already-public bug.

## Mitigation reminder

If you operate vulnerable infrastructure, the canonical mitigation is:

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Or update to a kernel including mainline commit `a664bf3d603d`.
