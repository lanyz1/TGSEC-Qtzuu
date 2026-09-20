

# Void - ICMP Stealth LKM Backdoor
```text
___   ___           ___
| |  / /___  (_)___/ /
| | / / __ \/ / __  / 
| |/ / /_/ / / /_/ /  
|___/\____/_/\__,_/   

ICMP LKM - Fully operational for King of the Hill style competition / RT engagements
```

An advanced, stealthy Linux Kernel Module (LKM) backdoor that uses ICMP (ping) for command and control (C2). The backdoor masquerades as an ALSA audio codec driver to blend in with normal system components and employs several evasion techniques to remain undetected.

> **Authorized testing only.** Everything here assumes a legal engagement: a signed penetration test, a bug-bounty program in scope, or your own lab / CTF. You are responsible for staying in scope and within the rules of engagement.

## Architecture
The project consists of three main components:

1. **`snd_hda_codec.c`**: The core Linux Kernel Module. It registers a Netfilter hook to inspect incoming ICMP Echo Request (Type 8) packets. It runs entirely in kernel space and executes commands using `call_usermodehelper` in a dedicated workqueue.
2. **`dev.injector.py`**: The attacker's Python client. It crafts specialized ICMP packets, handles encryption/encoding, and provides an interactive shell-like interface to communicate with the LKM.
3. **`setup.sh`**: The target deployment script. It compiles the C module, injects it into the kernel, intelligently chooses an obfuscated name based on the target's hardware profile, and rigorously scrubs system logs and bash history.

## Core Features & Stealth Mechanisms
- **Covert C2 Channel**: Communicates purely over ICMP Echo Requests. No open ports, no TCP/UDP bind shells.
- **Payload Obfuscation**: All payloads are Base64 encoded and XOR encrypted (using a hardcoded 8-byte key) before being sent over the wire.
- **Traffic Blending**: Packets are padded with standard ICMP data patterns to exactly match the length and signature of legitimate ping requests (e.g., 56-byte payload / 64-byte total).
- **Module Hiding**: Can dynamically unlink itself from the kernel's module list (hiding from `lsmod`) while remaining fully functional.
- **Session State & Timeouts**: Commands are ignored unless an initial `SYNC` packet is received, which opens a temporary (120-second) processing window, reducing the attack surface against random network noise.

## Built-in Commands
The backdoor supports several hardcoded "special" operations that run instantly via prefixed commands, alongside arbitrary shell command execution:

| Command | Internal Prefix | Description |
|---|---|---|
| `sync` | `SYNC:` | Authenticates the session and opens the 120s command processing window. |
| (Arbitrary) | `AUD:` | Executes a standard shell command via `/bin/sh -c`. |
| `hide` | `HID:` | Detaches the LKM from the kernel module list (invisible to `lsmod`). |
| `unhide` | `UNH:` | Re-attaches the LKM to the module list. |
| `ssh-key-quick` | `SSHQ:` | Injects a hardcoded Ed25519 public key into `/root/.ssh/authorized_keys`. |
| `ssh-key-full` | `SSHF:` | Injects the SSH key AND modifies `/etc/ssh/sshd_config` to explicitly permit root login. |
| `rogue-user` | `ROGU:` | Creates a hidden sudoer user (`toor` with password `changeme`) and injects the SSH key. |
| `rogue-cleanup` | `ROGC:` | Completely removes the `toor` user and its traces. |
| `chisel` | `CHIS:` | Automatically downloads `chisel` on the target and spawns a reverse tunnel back to the attacker's IP (extracted from the ICMP packet source). |

## Usage
### 1. Deployment (Target Machine)
Transfer `setup.sh` and `snd_hda_codec.c` to the target. Run the setup script as root:
```bash
sudo ./setup.sh
```

The script will automatically:
- Install necessary build dependencies (kernel headers, GCC).
- Hash the CPU and motherboard info to pick a realistic ALSA module name (e.g., `ALC892`, `ALC1220`).
- Compile and load the module.
- Shred `.bash_history` and clear tracks.

### 2. Interaction (Attacker Machine)
Run the Python injector with root privileges (required to craft raw sockets):
```bash
sudo python3 dev.injector.py <TARGET_IP>
```
