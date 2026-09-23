# Detection artifacts

Defender-side outputs paired with the offensive vectors.

## Layout

```
detection/
├── sigma/copyfail-af-alg.yml       Sigma rule (auditd-sourced)
├── auditd/copyfail.rules            auditd ruleset (drop into /etc/audit/rules.d/)
├── ebpf/copyfail-trace.bt           bpftrace one-liner (live tracing)
├── apparmor/copyfail-block.profile  AppArmor 3.0+ profile (blocks AF_ALG for unprivileged)
└── mitigation/disable-algif.sh      Modprobe blacklist + =y warning
```

## What each artifact does

| Artifact | Detects / does | Effective when |
|----------|---------------|----------------|
| `sigma/copyfail-af-alg.yml` | Non-root creates AF_ALG socket type=aead | auditd active before exploit |
| `auditd/copyfail.rules` | Logs every AF_ALG socket creation | rules loaded pre-exploit |
| `ebpf/copyfail-trace.bt` | Live tracing of AF_ALG sockets and (placeholder) bind/splice | bpftrace running during exploit |
| `apparmor/copyfail-block.profile` | Blocks AF_ALG socket creation for confined processes | AppArmor 3.0+, profile enforced |
| `mitigation/disable-algif.sh` | Blacklists `algif_aead` module via `install /bin/false` | `CONFIG_CRYPTO_USER_API_AEAD=m` (script warns if `=y`) |

## Detection-time vs. forensic detection

The Rust binary (`copyfail --mode detect --scan`) catches a successful
exploit *after the fact* by hashing files via O_DIRECT (disk) and via
buffered I/O (page cache) and comparing. This works when AIDE/OSSEC/Wazuh
fail because mainstream FIM tools read via buffered I/O and see the
mutated cache bytes as truth.

The artifacts above target detection *during* the exploit:

- **eBPF / auditd** fire on the syscall sequence (socket → bind → splice).
- **AppArmor** prevents the syscall sequence from succeeding at all.
- **Modprobe blacklist** prevents `algif_aead` from being loaded; module
  must be loaded for AF_ALG `aead` binds to succeed.

## Coverage matrix

| Vector | --scan diff | Sigma | auditd | eBPF | AppArmor block |
|--------|-------------|-------|--------|------|----------------|
| su (binary mutation) | ✓ | ✓ | ✓ | ✓ | ✓ |
| passwd (UID flip) | ✓ | ✓ | ✓ | ✓ | ✓ |
| pam (auth bypass) | ✓ | ✓ | ✓ | ✓ | ✓ |
| AF_ALG aead socket creation by non-root | n/a | ✓ | ✓ | ✓ | ✓ |
| splice() with crypto fd | n/a | n/a | partial | placeholder | n/a |

## Loading on Ubuntu test VM

```bash
# auditd
sudo cp auditd/copyfail.rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | grep copyfail

# bpftrace (one-shot)
sudo bpftrace ebpf/copyfail-trace.bt

# AppArmor (Ubuntu 24.04 has AppArmor 3.x)
sudo cp apparmor/copyfail-block.profile /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/copyfail-block.profile

# Modprobe mitigation
sudo bash mitigation/disable-algif.sh
```

## Future work

- C eBPF program with LSM hooks (replace bpftrace placeholder for splice tracking)
- Falco rule for container runtimes (Kubernetes worker nodes)
- SIEM connectors (Splunk SPL, Elastic Detection Engine query)
- Cross-file correlation: AF_ALG socket creation + splice() to crypto fd within N ms
