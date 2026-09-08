# OpenSSH Forwarded-Agent Lock Provider Bypass PoC

This entry demonstrates a state transition in portable OpenSSH `ssh-agent` that lets a forwarded agent connection reach the provider-add path after the agent moves from locked to unlocked. The replay uses an unchanged release build of OpenSSH `10.4p1`, an actual `ssh -A` connection, public-key authentication, and a stock `sshd` listener.

The remote process keeps its forwarded `SSH_AUTH_SOCK` connection open while the agent is locked. The client sends `session-bind@openssh.com`, the locked agent rejects the extension request, and the SSH client still creates the forwarded agent channel. When the agent is unlocked through a separate local connection, the persistent forwarded socket has neither a recorded session identifier nor the failed-bind marker used by `socket_is_remote()`. A provider-add request on that socket is consequently handled as a local request.

## Tested Target

| Field | Value |
| --- | --- |
| Product | OpenSSH portable |
| Release | `10.4p1` |
| Release date | July 6, 2026 |
| Platform | Ubuntu 24.04.4 LTS x86-64 under WSL2 |
| Kernel | Linux `6.6.87.2-microsoft-standard-WSL2` |
| Crypto library | OpenSSL `3.0.13` |
| Source archive | `openssh-10.4p1.tar.gz` |
| Archive SHA-256 | `ef6026dd2aea8d56059638d5d3262902c892ceba9f88395835e0d06d3fb63238` |
| `ssh-agent` SHA-256 | `c50a8cd9b1016dccfd21cb9b2f98e0de5285c27a0db87a8a7ae464bcd40d2e0d` |
| `ssh` SHA-256 | `d41006f31c89164da9f3c778f085d56cc0077ff49b1aca361863386ed8a068e9` |
| `sshd` SHA-256 | `7420fe8020cb3e4a895f3c7eecd3327bcca78f6b4c28b3c6a267b6cfb1cfcdb9` |
| Provider used for replay | `/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so` |

The archive checksum matched the OpenSSH release checksum. Its detached signature verified with OpenSSH release key fingerprint `7168 B983 815A 5EEF 59A4 ADFD 2A3F 414E 7360 60BA`. The binaries were produced with the release `configure`, `make`, and `make install` flow.

## Files

| Path | Purpose |
| --- | --- |
| [`poc.py`](poc.py) | Sends agent lock and unlock requests and issues the provider request through the real forwarded socket. |
| [`run.sh`](run.sh) | Starts the selected stock OpenSSH binaries, creates an isolated loopback SSH configuration, drives the sequence, and verifies the diagnostic markers. |
| [`evidence/stock-openssh-10.4p1.txt`](evidence/stock-openssh-10.4p1.txt) | Output and selected stock-process diagnostics from the repository replay. |

## Root Cause

The state mismatch spans the OpenSSH client and agent:

1. `clientloop.c` creates a new forwarded agent channel in `client_request_agent()` even when `ssh_agent_bind_hostkey()` reports that the agent refused the session bind.
2. `ssh-agent.c` extracts the request type in `process_message()` and applies the global locked check before its main dispatcher.
3. While locked, every extension request is discarded before `process_extension()` can parse its name.
4. `process_ext_session_bind()` therefore never sets `session_bind_attempted` for the forwarded socket.
5. After a separate local socket unlocks the agent, `socket_is_remote()` sees both `session_bind_attempted` and the session-identifier count as zero.
6. `process_add_smartcard_key()` accepts the provider request because its remote-socket condition evaluates false.
7. `pkcs11_add_provider()` starts `ssh-pkcs11-helper`, which loads the selected module, resolves the PKCS#11 entry point, and initializes the provider.

The same socket classification is consulted by the external security-key provider path.

## Source Trace

| Source | Function | Role |
| --- | --- | --- |
| `clientloop.c` | `client_request_agent()` | Attempts session binding, logs a refusal, and still creates the agent-forwarding channel. |
| `ssh-agent.c` | `process_message()` | Rejects extension messages at the locked gate before extension dispatch. |
| `ssh-agent.c` | `process_extension()` | Routes `session-bind@openssh.com` only after the locked gate. |
| `ssh-agent.c` | `process_ext_session_bind()` | Sets `session_bind_attempted` and records verified session identifiers. |
| `ssh-agent.c` | `socket_is_remote()` | Classifies a socket from the failed-bind marker and recorded session identifiers. |
| `ssh-agent.c` | `process_add_smartcard_key()` | Applies the remote-provider restriction before calling the PKCS#11 layer. |
| `ssh-agent.c` | `process_add_identity()` | Applies the same classification to external security-key providers. |
| `ssh-pkcs11.c` | `pkcs11_add_provider()` | Sends the provider request to the helper. |
| `ssh-pkcs11.c` | provider initialization path | Loads the module and invokes its PKCS#11 initialization routine. |

## Replay Sequence

`run.sh` performs the following sequence with the binaries selected by `OPENSSH_PREFIX`:

1. Generate temporary Ed25519 host and client keys.
2. Start the selected `ssh-agent` on an isolated Unix socket.
3. Start the selected `sshd` on loopback with public-key authentication and agent forwarding enabled.
4. Lock the agent through its protocol.
5. Connect with the selected `ssh -A` and run `poc.py probe` as the remote process.
6. Hold the real forwarded agent socket open after the locked agent refuses session binding.
7. Unlock the agent through a separate local socket.
8. Send `SSH_AGENTC_ADD_SMARTCARD_KEY` through the persistent forwarded socket.
9. Require the stock client log to show the refused bind followed by agent-channel creation.
10. Require the stock agent log to show helper startup and provider initialization.

The temporary listener accepts connections only on `127.0.0.1`, disables password authentication, and uses a generated key dedicated to the replay.

## Prerequisites

- Linux with Python 3, `sudo`, and the OpenSSH privilege-separation account used by `sshd`.
- A stock portable OpenSSH installation containing `ssh`, `sshd`, `ssh-agent`, and `ssh-keygen` under one prefix.
- A PKCS#11 module permitted by the agent's provider allowlist.
- A free loopback TCP port.

On Ubuntu 24.04 x86-64, the default provider path used by the script is supplied by `p11-kit-modules`.

## Usage

Run from this folder and point `OPENSSH_PREFIX` at the stock installation:

```sh
OPENSSH_PREFIX=/opt/openssh-10.4p1 bash run.sh
```

The listener defaults to port `22991`. Select another port when needed:

```sh
OPENSSH_PREFIX=/opt/openssh-10.4p1 PORT=23022 bash run.sh
```

Select a different permitted provider with `PROVIDER`:

```sh
OPENSSH_PREFIX=/opt/openssh-10.4p1 \
PROVIDER=/usr/lib/x86_64-linux-gnu/pkcs11/example.so \
bash run.sh
```

Preserve the generated client, agent, and server logs with `KEEP=1`:

```sh
OPENSSH_PREFIX=/opt/openssh-10.4p1 KEEP=1 bash run.sh
```

## Expected Output

A successful replay prints:

```text
lock_reply_type=6
unlock_reply_type=6
forwarded_socket_connected=true
provider_reply_type=5
target=OpenSSH_10.4p1, OpenSSL 3.0.13 30 Jan 2024
session_bind_refused_while_locked=true
forwarded_channel_opened=true
provider_helper_started=true
provider_initialized=true
reproduced=true
```

The stock client trace contains these ordering markers:

```text
client_request_agent: ssh_agent_bind_hostkey: agent refused operation
channel 1: new agent-connection [authentication agent connection]
confirm agent-connect
```

The stock agent trace contains:

```text
agent locked
process_message: socket 1 type 27
agent unlocked
process_message: socket 1 type 20
process_add_smartcard_key: add /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so
pkcs11_start_helper: starting .../ssh-pkcs11-helper -vvv
provider /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so: manufacturerID <PKCS#11 Kit>
```

The protocol reply is emitted after the helper has loaded and initialized the provider. The replay decision is based on the ordered client and agent diagnostics rather than the final reply byte.

## Version Inspection

The locked-dispatch ordering and the provider classification path are present in the portable tags `V_9_3_P2`, `V_9_4_P1`, `V_9_5_P1`, `V_9_6_P1`, `V_10_0_P2`, `V_10_3_P1`, and `V_10_4_P1`. The provider restriction begins in `9.3p2`; the additional failed-session-bind tracking begins in `9.6p1` and remains behind the locked gate for this sequence.

## Repair Direction

Process `session-bind@openssh.com` while the agent is locked so the per-socket security state is recorded before any later unlock. Extension handling at the locked gate should admit only operations explicitly designed for locked state. Regression coverage should preserve the forwarded socket across lock and unlock, then verify that provider addition remains classified as remote.

## References

- [OpenSSH portable 10.4p1 source archive](https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.4p1.tar.gz)
- [OpenSSH agent restriction design](https://www.openbsd.org/openssh/agent-restrict.html)
- [ssh-agent manual](https://man.openbsd.org/ssh-agent.1)

## Responsible Use

Use this material only on systems you own or have explicit permission to test.
