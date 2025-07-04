# ReconX - Advanced Cybersecurity Reconnaissance & Vulnerability Analysis Tool

Professional modular cybersecurity reconnaissance and vulnerability analysis tool with interactive menu system and comprehensive exploit detection capabilities.

## Features

- **Interactive Menu System**: User-friendly interface for all operations
- **Advanced Port Scanning**: NMAP-powered comprehensive port discovery with service detection
- **Vulnerability Scanning**: CVE detection, NSE scripts, and exploit matching
- **DNS Reconnaissance**: A, MX, TXT, NS records and subdomain enumeration
- **HTTP Analysis**: Server information, header analysis and directory fuzzing
- **FTP Analysis**: Anonymous login testing and banner grabbing
- **Exploit Database Integration**: Automated exploit discovery for found vulnerabilities
- **Security Assessment**: Risk-based vulnerability prioritization
- **Advanced Reporting**: HTML and JSON report generation with vulnerability details
- **Modular Architecture**: Easily extensible framework
- **Professional Output**: Clean terminal visualization without emojis
- **Flexible Configuration**: Customizable timeout and scan options

## Prerequisites

- Python 3.6+
- NMAP (for port scanning)

```bash
# Install NMAP
sudo apt install nmap

# Install Python dependencies
pip install -r requirements.txt
```

## Usage Modes

### 1. Interactive Mode (Recommended)
```bash
python reconx_interactive.py
```

**Interactive Menu Options:**
- `[1]` Set Target (IP/Domain)
- `[2]` Port Scanning (Fast/Full/Stealth/Service/OS/Aggressive)
- `[3]` DNS Reconnaissance
- `[4]` HTTP Analysis  
- `[5]` FTP Analysis
- `[6]` **Vulnerability Scanning** (NEW!)
- `[7]` Full Reconnaissance (includes vulnerability analysis)
- `[8]` Generate Reports (JSON/HTML)
- `[9]` Settings

### 2. Command Line Mode
```bash
python reconx.py --target example.com
python reconx.py --target 192.168.1.10 --timeout 10 --json results.json
```

## Supported Modules

1. **Port Scanning** (`modules/port_scan.py`)
   - NMAP-powered port discovery
   - Multiple scan types (Fast/Full/Stealth/Service/OS/Aggressive)
   - Custom port ranges
   - Service version detection

2. **Vulnerability Scanning** (`modules/vulnerability_scanner.py`)
   - NSE vulnerability script automation
   - CVE database integration
   - Exploit matching and discovery
   - Risk-based severity assessment
   - CVSS scoring system

3. **DNS Reconnaissance** (`modules/dns_scan.py`)
   - A, MX, TXT, NS record queries
   - Subdomain enumeration with built-in wordlist
   - Reverse DNS lookups

4. **HTTP Analysis** (`modules/http_probe.py`)
   - HTTP/HTTPS service detection
   - Server information and header analysis
   - Common path discovery
   - Security header validation
   - Vulnerability identification

5. **FTP Analysis** (`modules/ftp_scan.py`)
   - FTP service detection
   - Anonymous login testing
   - Banner grabbing
   - Directory listing
   - FTP bounce attack testing

## Vulnerability Scanning Features

### NSE Script Integration
- **Web Services**: `http-vuln-*`, `ssl-heartbleed`, `ssl-poodle`
- **SMB Services**: `smb-vuln-ms17-010`, `smb-vuln-ms08-067`
- **FTP Services**: `ftp-anon`, `ftp-bounce`
- **SSH Services**: `ssh-hostkey`, `ssh-auth-methods`

### CVE Database Integration
- Apache, MySQL, OpenSSH, nginx vulnerability detection
- CVSS scoring and severity classification
- Year-based CVE tracking
- Automated CVE-to-exploit matching

### Risk Assessment
- **[CRITICAL]** CVSS 9.0+ (Immediate action required)
- **[HIGH]** CVSS 7.0+ (High priority patching)
- **[MEDIUM]** CVSS 4.0+ (Scheduled patching)
- **[LOW]** CVSS <4.0 (Monitor and assess)

### Exploit Integration
- ExploitDB integration
- Metasploit module recommendations
- Exploit availability tracking
- Direct links to exploit resources

## Sample Output

```
VULNERABILITY SCAN SUMMARY:
Target: 192.168.1.10
Total Vulnerabilities: 8
[CRITICAL] 2
[HIGH] 3
[MEDIUM] 2
[LOW] 1

VULNERABILITIES WITH EXPLOITS:
[CRITICAL] CVE-2021-41773: Apache HTTP Server Path Traversal -> 2 exploits
    |- exploit-db: Apache 2.4.49 - Path Traversal RCE
    |- metasploit: Apache Path Traversal

[HIGH] CVE-2021-42013: Apache HTTP Server Path Traversal and RCE -> 2 exploits
    |- exploit-db: Apache 2.4.49/2.4.50 - Path Traversal and RCE
    |- metasploit: Apache Normalize Path RCE

[ALERT] TOTAL: 7 exploits found for discovered vulnerabilities!

[ALERT] IMMEDIATE ACTION REQUIRED!
   Critical/High severity vulnerabilities detected!
```

## Report Generation

### HTML Reports
- Professional vulnerability analysis reports
- Severity-based vulnerability grouping
- Exploit details and recommendations
- CVSS scoring and risk assessment
- Color-coded vulnerability cards

### JSON Reports
- Machine-readable results for automation
- Complete vulnerability data
- Integration with security tools
- API-friendly format

## Quick Start

1. **Set Target and Run Vulnerability Scan:**
```bash
cd reconx
python reconx_interactive.py

# In menu:
[1] -> Enter target: 192.168.1.10
[6] -> Vulnerability Scanning
```

2. **Full Security Analysis:**
```bash
# Select option [7] for complete reconnaissance + vulnerability analysis
# Automatically generates comprehensive security reports
```

## Security Notice

This tool is designed for authorized security testing and educational purposes only. 
Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical.

## License

This project is developed for educational and research purposes. 