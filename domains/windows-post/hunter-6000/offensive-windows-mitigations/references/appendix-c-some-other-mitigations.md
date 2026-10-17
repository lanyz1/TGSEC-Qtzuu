## Appendix C: Some Other Mitigations

### Administrator Protection (Windows 11 24H2+)

**What is Administrator Protection?**:

- Enhanced replacement for traditional UAC Admin Approval Mode
- Creates temporary, just-in-time elevated admin accounts
- Temporary admin context destroyed after elevation completes
- Prevents persistent admin tokens from being stolen/abused

**How It Works**:

```text
Traditional UAC Admin Approval:
--------------------------------------------------------------

User in Administrators group has TWO tokens:
- Standard user token (used by default)
- Admin token (used after UAC prompt)

Problem: Admin token PERSISTS in session
         Token theft attacks (e.g., token impersonation) can abuse it

Administrator Protection:
--------------------------------------------------------------

User requests elevation:
1. System creates TEMPORARY hidden admin account
2. New admin token generated just-in-time
3. Elevated action performed
4. Temporary admin account/token DESTROYED
5. No persistent admin token to steal!

Security Benefit:
- Token theft has limited window
- Pass-the-hash harder (no persistent high-priv token)
- Mimikatz token impersonation much less effective
```

**Enabling Administrator Protection**:

```powershell
# Check current status (Windows 11 24H2+)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "TypeOfAdminApprovalMode" -ErrorAction SilentlyContinue

# Values:
# 0 = Admin Approval Mode disabled (not recommended)
# 1 = Traditional Admin Approval Mode (default)
# 2 = Admin Approval Mode with Administrator Protection (enhanced)

# Enable via Group Policy:
# Computer Configuration -> Windows Settings -> Security Settings ->
# Local Policies -> Security Options ->
# "User Account Control: Configure type of Admin Approval Mode"
# Set to: "Admin Approval Mode with Administrator Protection"

# Or via Registry (for testing):
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v TypeOfAdminApprovalMode /t REG_DWORD /d 2 /f

# Restart required for changes to take effect
```

### Personal Data Encryption (PDE)

**What is PDE?**:

- File-level AES-256 encryption for known folders
- Protected by Windows Hello for Business authentication
- Separate from BitLocker (provides per-user protection)
- Data stays encrypted until user authenticates via Windows Hello

**Protected Folders**:

- Desktop
- Documents
- Pictures

**How PDE Differs from BitLocker**:

| Feature            | BitLocker     | PDE                    |
| ------------------ | ------------- | ---------------------- |
| Scope              | Full disk     | Per-user folders       |
| Key Storage        | TPM           | User container (VBS)   |
| Unlock Mechanism   | Boot PIN/Auto | Windows Hello          |
| Multi-user support | N/A           | Each user has own keys |
| Offline attack     | Protected     | Protected + user-bound |

**Checking PDE Status**:

```powershell
# Requires Windows 11 22H2+ with Windows Hello for Business

# Check if PDE is enabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\PDE" -ErrorAction SilentlyContinue

# PDE requires:
# - Windows 11 Enterprise/Education (NOT available on Pro/Home)
# - Windows Hello for Business enrolled
# - VBS enabled (for key protection)

# Check Windows edition
(Get-ComputerInfo).WindowsEditionId

# Note: Empty output means PDE is not configured
```

### Enhanced Sign-in Security (ESS)

**What is ESS?**:

- VBS-protected biometric data processing
- Isolates face/fingerprint authentication in secure virtualization environment
- Prevents biometric replay attacks
- Secure channel between biometric sensors and Windows Hello

**Architecture**:

```text
Without ESS:
---------------------------------------------------------------------------------------
Biometric Sensor -> Standard Driver -> Windows Hello -> Credential Provider
                   ↑
        Potential attack surface (driver vulnerabilities)

With ESS:
---------------------------------------------------------------------------------------
Biometric Sensor -> ESS-capable Driver -> [VTL 1 Secure Processing] -> Credential Provider
                                        ↑
                           Isolated from kernel/malware
                           Biometric data never exposed to VTL 0

Attack Mitigation:
- Biometric data can't be extracted by malware
- Replay attacks blocked at hardware level
- Driver compromises can't steal biometric templates
```

**Requirements**:

- ESS-capable biometric hardware (fingerprint sensors, IR cameras)
- Default on Copilot+ PCs
- Manual enable on supported hardware otherwise

**Checking ESS Status**:

```powershell
# Check if ESS is enabled
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object -Property EnhancedSignInSecurity*

# Look for: EnhancedSignInSecuritySupported, EnhancedSignInSecurityMode
# Note: Empty output means ESS properties not available (no ESS-capable hardware)

# Check if you have biometric hardware at all
Get-PnpDevice | Where-Object {$_.Class -eq "Biometric"}

# If no biometric devices found, ESS is not applicable to your system
```

### Passkeys (FIDO2 Passwordless Authentication)

**What are Passkeys?**:

- Native FIDO2 passwordless authentication in Windows 11
- Hardware-backed credentials using TPM
- Cross-device sync via Microsoft account
- Phishing-resistant (bound to specific domains)

**Security Benefits**:

```text
Password vs. Passkey Security:
------------------------------------------------------

Traditional Password:
- Can be phished (user types on fake site)
- Can be credential-stuffed (reused passwords)
- Can be brute-forced (weak passwords)
- Stored on server (breach = mass compromise)

Passkey (FIDO2):
- Domain-bound (can't be phished to wrong site)
- Unique per site (no credential stuffing)
- Hardware-backed (can't be brute-forced)
- Public key on server (breach = harmless data)

Attack Surface Reduction:
- Eliminates password guessing attacks
- Eliminates phishing credential theft
- Eliminates password spray attacks
```

**Windows Passkey Management**:

```text
# Passkeys stored in Windows Hello credential provider
# Access via Settings -> Accounts -> Passkeys

# Or programmatically query:
# Uses WebAuthn APIs (Windows.Security.Credentials)
```

### Enhanced Phishing Protection

**What is Enhanced Phishing Protection?**:

- SmartScreen-based password protection
- Detects password entry on known phishing sites
- Warns when reusing work passwords on non-work sites
- Alerts on unsafe password storage (plaintext in files)

**Protection Modes**:

| Alert Type             | Trigger                            | Impact                       |
| ---------------------- | ---------------------------------- | ---------------------------- |
| Phishing site warning  | Typing password on malicious site  | Blocks credential submission |
| Password reuse warning | Using work password elsewhere      | Warning notification         |
| Unsafe storage warning | Saving password in plaintext files | Warning notification         |

**Enabling**:

```text
# Via Group Policy:
# Computer Configuration -> Administrative Templates -> Windows Components ->
# Windows Defender SmartScreen -> Enhanced Phishing Protection

# Settings:
# - Notify Malicious: Warn on phishing sites
# - Notify Password Reuse: Warn on corporate password reuse
# - Notify Unsafe App: Warn on plaintext password storage
```

### SMB Protocol Hardening (Windows 11 24H2+)

**What Changed**:

- SMB signing now **required by default** (previously optional)
- SMB NTLM blocking capability added
- SMB encryption mandate capability
- SMB over QUIC client access control

**Security Impact**:

```text
SMB Relay Attacks Before 24H2:
--------------------------------------------------------------
Attacker intercepts SMB traffic -> Relays to another server
Works because signing was optional by default

SMB After 24H2:
--------------------------------------------------------------
All SMB traffic MUST be signed
Relay attacks fail (signature verification fails)
```

**Checking SMB Signing Status**:

```bash
# Check SMB server configuration
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature

# Check SMB client configuration
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature

# Windows 11 24H2 defaults:
# RequireSecuritySignature = True
```

### NTLMv1 Removal

**What Changed**:

- NTLMv1 is **completely removed** in Windows 11 24H2 and Windows Server 2025
- NTLMv2 still available (but deprecation planned)
- Kerberos is the default and recommended authentication protocol

**Impact on Attacks**:

```text
NTLM Attack Surface Before:
--------------------------------------------------------------
NTLMv1 is cryptographically weak:
- Rainbow table attacks feasible
- Relay attacks easier
- Downgrade attacks possible

After NTLMv1 Removal:
--------------------------------------------------------------
- No downgrade from NTLMv2 to v1 possible
- Legacy attacks eliminated
- Responder/relay attacks harder
```

**Checking NTLM Configuration**:

```powershell
# Check which NTLM versions are allowed
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

# Values (if key exists):
# 0-1: LM and NTLMv1 allowed (legacy, insecure)
# 2: NTLMv1 allowed
# 3-4: NTLMv2 only
# 5: NTLMv2 only, refuse LM/NTLMv1

# Note: In Windows 11 24H2+, this key may not exist by default
# Absence of key = NTLMv1 removed, NTLMv2 only (secure default)

# Check if LM hashes are disabled (should be 1)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue

# Check NTLM session security requirements
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue | Select-Object NtlmMinClientSec, NtlmMinServerSec

# Common secure values:
# NtlmMinClientSec/NtlmMinServerSec = 536870912 (0x20000000)
# Means: Require NTLMv2 session security + 128-bit encryption
```

### Rust in Windows Kernel (Memory Safety)

**What Changed**:

- Parts of Windows kernel now written in Rust
- Win32k GDI region code rewritten (reported as `win32kbase_rs.sys`; shipping name may vary by build)
- Memory-safe language eliminates entire bug classes

**Security Impact**:

```text
Traditional C/C++ Kernel Code:
-------------------------------------------------------------
Vulnerable to:
- Buffer overflows
- Use-after-free
- Type confusion
- Integer overflows
- Null pointer dereferences

Rust Kernel Code:
-------------------------------------------------------------
Eliminated by design:
- Buffer overflows (bounds checking)
- Use-after-free (ownership model)
- Data races (borrow checker)
- Null dereferences (Option types)

Remaining attack surface:
- Logic bugs (Rust doesn't prevent these)
- unsafe{} blocks (audited carefully)
- FFI boundaries (C/Rust interface)
```

**Why This Matters**:

```text
Win32k.sys Vulnerability History:
-------------------------------------------------------------
Win32k has been the #1 kernel attack surface for a decade
- Hundreds of CVEs (mostly memory corruption)
- Complex codebase with legacy debt

Rust Rewrite Impact:
- Future memory corruption bugs in GDI nearly impossible
- Attackers must find logic bugs instead
- Significantly raises exploitation difficulty
```

### Windows Protected Print Mode (24H2)

**What is Protected Print Mode?**:

- Modern print stack using only Mopria-certified drivers
- Eliminates third-party print drivers (major attack surface)
- Driver vulnerabilities have historically been popular attack vectors

**Security Impact**:

```text
Traditional Print Stack Attack Surface:
-------------------------------------------------------------
Third-party print drivers loaded into:
- Print Spooler (SYSTEM context)
- Kernel mode (some drivers)
- User applications

Historical CVEs:
- PrintNightmare (CVE-2021-34527)
- Many spooler vulnerabilities
- Driver loading = code execution

Protected Print Mode:
-------------------------------------------------------------
Only certified drivers allowed:
- Mopria-certified (standardized, audited)
- No arbitrary kernel code loading
- Reduced privilege for print operations

Attack surface massively reduced
```

### Key Takeaways - New Mitigations

1. **Administrator Protection** eliminates persistent admin tokens (anti-mimikatz)
2. **PDE** provides per-user file encryption beyond BitLocker
3. **ESS** isolates biometric processing in VBS (anti-biometric theft)
4. **Passkeys** eliminate password-based attacks entirely
5. **SMB Signing Required** breaks relay attacks by default
6. **NTLMv1 Removal** eliminates legacy authentication weaknesses
7. **Rust in Kernel** eliminates memory corruption bug classes
8. **Protected Print** removes historically vulnerable driver attack surface

### Discussion Questions - New Mitigations

1. How does Administrator Protection affect red team token manipulation techniques?
2. Can PDE protected folders be accessed by malware running as the authenticated user?
3. What happens to passkeys if your TPM is cleared or hardware changes?
4. How would you test if SMB signing is properly enforced in an enterprise?
5. What types of vulnerabilities can still occur in Rust kernel code?

