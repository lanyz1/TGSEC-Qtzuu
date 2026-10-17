#  Port Scanner v3.1 🍓

## 🌟 Introduction
** Port Scanner** is an advanced network scanning tool featuring:
- High-performance multithreaded scanning
- Automatic service detection
- Security severity classification
- Beautiful purple-themed UI with strawberry accents

## ✨ Latest Updates (v3.1)
- UI Improvements: Perfectly aligned output tables
- Enhanced Reporting:
  - JSON export with full scan details
  - Automatic logging (scan_YYYY-MM-DD.log)
- Performance Optimizations:
  - Smart thread management based on CPU cores
  - Reduced resource usage
- Security Upgrades:
  - Legal disclaimer on startup
  - Automatic sensitive data cleanup

## 🚀 Key Features
✔️ Multithreaded TCP/UDP scanning  
✔️ Auto-detection of 150+ common services  
✔️ Security severity classification (Critical/High/Medium/Low)  
✔️ Custom port range support (e.g., 20-500)  
✔️ Dual output modes:  
   - Beautiful console tables  
   - JSON files for further analysis  
✔️ Cross-platform (Windows/Linux/macOS) 

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

### Pro Tips for Deployment:
# Make executable
```bash
chmod +x port_scanner.py

# Create a release package
zip _PortScanner_v3.1.zip port_scanner.py requirements.txt README.md

#clone the repository
git clone https://github.com//Port_Scanner.git
cd Port_Scanner-tools

# install dependencies
pip install -r requirements.txt

# run the scanner
python port_scanner.py

# Usage
1. basic scan (default ports):
```bash
Enter target IP/hostname: example.com
Protocol (tcp/udp): tcp

2. custom port range:
```bash
Enter port/range: 80-500

3. UDP scan:
```bash
Protocol (tcp/udp): udp

# Sample Output
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧
              OPEN PORTS FOUND  
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧
No.  Port    Service           Protocol    Severity
---------------------------------------------------
1    22      SSH               TCP         Critical
2    80      HTTP              TCP         High
3    443     HTTPS             TCP         Critical
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧
           Total open ports found: 3 
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧