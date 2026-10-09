> # ⚠️ Authorized use only
>
> BlackSentinel Strike is an **offensive security** toolkit for **authorized**
> penetration testing and red-team work. Running it against systems you do not
> own or do not have **explicit, written permission** to test is illegal in most
> jurisdictions and is never permitted.
>
> By using this software you confirm that:
> - you have written authorization for every target and every technique you run;
> - you stay within the agreed scope (see the built-in scope controls);
> - you are solely responsible for how you use it.
>
> It is provided as a **technical preview**, as-is, with no warranty. See the
> [Acceptable Use Policy](https://blacksentinel.tech/acceptable-use/). The authors
> accept no liability for misuse.

# BlackSentinel Pentest Suite v4.0

**Professional Penetration Testing Platform with AES-256-CBC Encrypted Storage**

---

## Author

**BlackSentinel Strike**
Cybersecurity and Autonomous Defense
*Cybersecurity and Autonomous Defense Engineer*

---

## About This Project

### What Is It?

BlackSentinel Pentest Suite is an all-in-one penetration testing GUI application built for authorized security professionals. It integrates 12+ industry-standard security tools into a single unified interface with military-grade AES-256-CBC encryption to protect all scan data, operator metadata, and configuration.

### Why Was It Created?

- **Centralized Workflow**: Instead of running 12+ security tools from separate terminals, everything is accessible from one interface
- **Data Protection**: All scan results and operator metadata are encrypted at rest using AES-256-CBC with HMAC-SHA512 and PBKDF2-SHA512 (1,000,000 iterations)
- **Audit Trail**: Every scan is timestamped and encrypted, creating a tamper-proof record of all testing activities
- **Productivity**: Real-time output streaming, one-click tool execution, automated report generation
- **Deployment Ready**: Can be installed on company servers for team use with Docker
- **Kali Linux Ready**: Full support for Kali Linux with automated deployment script

### What Does It Do?

| Capability | Description |
|------------|-------------|
| **Network Discovery** | Find live hosts on target networks using ping, SYN, and TCP connect scans |
| **Port Scanning** | Identify open ports and running services (1000 common to full 65535) |
| **Web Application Recon** | Fingerprint web servers, discover directories, test for SQL injection, scan for vulnerabilities |
| **Exploitation Framework** | Run nmap vulnerability scripts against known CVEs (EternalBlue, vsftpd, Struts2, etc.) |
| **Post-Exploitation** | Enumerate compromised systems (users, processes, network connections, password hashes) |
| **Password Attacks** | Brute-force SSH, FTP, HTTP, SMB, RDP, MySQL using hydra with configurable wordlists |
| **Reporting** | Generate structured penetration test reports with executive summary, methodology, findings, and recommendations |

### How Does It Work?

1. Launch the application (Python/CustomTkinter GUI)
2. Create or unlock an encrypted vault (AES-256)
3. Select a module from the sidebar
4. Configure target and scan parameters
5. Execute - the system runs the underlying tool in a background thread
6. Results stream in real-time to the output console
7. All results are automatically encrypted and saved to `~/.blacksentinel-strike/vault/scans/`
8. Generate reports from the collected data

### Who Is It For?

Authorized penetration testers, red team operators, and security auditors who need to perform authorized security assessments on systems they have written authorization to test.

---

## Architecture

```
blacksentinel-strike/
├── app.py                    # Main GUI application (1567 lines)
├── VERSION                   # Current version (4.0.0)
├── requirements.txt          # Python dependencies
├── deploy.sh                 # Automated deployment script
├── Dockerfile                # Docker deployment
├── MANUAL.md                 # Complete manual (English)
├── MANUAL_ES.md              # Complete manual (Spanish)
├── README.md                 # This file
└── modules/
    ├── __init__.py
    ├── vault.py              # AES-256 encryption engine
    ├── network_utils.py      # IP jumper, DNS, MAC randomization
    ├── updater.py            # Auto-upgrade system
    ├── recon.py              # Network reconnaissance
    ├── web.py                # Web application analysis
    ├── exploits.py           # Exploitation framework
    ├── bruteforce.py         # Password brute-force attacks
    ├── postexploit.py        # Post-exploitation enumeration
    ├── forensic.py           # Forensic analysis
    ├── wireless.py           # Wireless network attacks
    ├── network_attacks.py    # Network-level attacks
    ├── social_engineering.py # Social engineering tools
    ├── reports.py            # Report generation
    ├── themes.py             # UI theme definitions
    └── utils.py              # Shared utilities
```

### Data Flow

```
User Input (GUI)
    ↓
Module Handler (app.py)
    ↓
Tool Execution (subprocess)
    ↓
Output Streaming (threading + queue)
    ↓
Encryption (vault.py - AES-256)
    ↓
Storage (~/.blacksentinel-strike/vault/scans/)
```

### Encryption Flow

```
Master Password
    ↓
PBKDF2-HMAC-SHA512 (1,000,000 iterations)
    ↓
AES-256-CBC Key (32 bytes)
    ↓
Fernet Token (encrypt/decrypt)
```

---

## Installation

### Prerequisites

- macOS (tested on Apple Silicon) or Linux
- Python 3.10+
- Homebrew (macOS) or apt (Linux)
- Internet connection (for initial tool installation)

### Quick Install

```bash
# Clone or copy the project
cd ~/hacks
git clone <repository-url> pentest-gui
cd pentest-gui

# Run the deployment script
bash deploy.sh

# Launch
python3 app.py
```

### Manual Install (Step by Step)

#### Step 1: Install Python dependencies

```bash
pip3 install --break-system-packages -r requirements.txt
```

#### Step 2: Install security tools

```bash
# macOS (Homebrew)
brew install nmap hydra nikto sqlmap gobuster masscan nuclei subfinder httpx ffuf

# WhatWeb (requires Ruby)
brew install ruby
git clone --depth 1 https://github.com/urbanadventurer/whatweb.git /opt/homebrew/opt/whatweb
cat > /opt/homebrew/bin/whatweb << 'EOF'
#!/bin/bash
exec /opt/homebrew/opt/ruby/bin/ruby /opt/homebrew/opt/whatweb/whatweb "$@"
EOF
chmod +x /opt/homebrew/bin/whatweb

# Dirsearch (Python)
pip3 install --break-system-packages dirsearch

# Wordlists
sudo mkdir -p /usr/share/wordlists/dirb
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    | sudo tee /usr/share/wordlists/dirb/common.txt > /dev/null
```

#### Step 3: Verify installation

```bash
for tool in nmap nikto sqlmap gobuster hydra whatweb masscan nuclei subfinder httpx ffuf dirsearch; do
    if command -v $tool >/dev/null 2>&1; then
        echo "[OK] $tool"
    else
        echo "[--] $tool NOT INSTALLED"
    fi
done
```

#### Step 4: Launch

```bash
python3 app.py
```

### Docker Install

```bash
# Build
docker build -t blacksentinel-strike .

# Run (with display forwarding for GUI)
docker run -it --net=host -e DISPLAY=$DISPLAY blacksentinel-strike

# Or run headless and access via VNC
docker run -it -p 5900:5900 blacksentinel-strike
```

---

## First Run & Vault Setup

When you launch the application for the first time:

1. A dialog appears: **"VAULT SETUP"**
2. Create a **master password** (minimum 4 characters)
3. This password encrypts ALL data: scan results, configuration, metadata
4. **THIS PASSWORD CANNOT BE RECOVERED** - write it down somewhere safe

### What the Vault Protects

| Data Type | Storage Location | Encryption |
|-----------|-----------------|------------|
| Scan results | `~/.blacksentinel-strike/vault/scans/*.enc` | AES-256 |
| Configuration | `~/.blacksentinel-strike/vault/config.enc` | AES-256 |
| Metadata (IP, MAC) | `~/.blacksentinel-strike/vault/metadata.enc` | AES-256 |
| Master key | `~/.blacksentinel-strike/vault/master.key` | PBKDF2-derived |
| Test token | `~/.blacksentinel-strike/vault/test.token` | AES-256 |

---

## Modules

### Dashboard
- Platform information (OS, kernel, Python version)
- Tool status verification (12 tools)
- Network info (hostname, local IP)
- Quick actions to other modules
- Real-time CPU/RAM monitoring

### War Exploit (NEW)
Automated attack pipeline that scans, detects vulnerabilities, and attempts exploitation:

1. **Port Scan** - Masscan/nmap discovers all open ports (65535)
2. **Service Detection** - Identifies running services and versions
3. **Vulnerability Scan** - Checks 40+ known CVEs and runs nuclei
4. **Exploitation** - Automatically attempts exploitation (EternalBlue, vsftpd, Struts2, ShellShock, etc.)
5. **Post-Exploitation** - Gathers system info if exploitation succeeds

**How to use:**
1. Enter target IP in "War Exploit" page
2. Click "ATTACK"
3. Watch the 5-stage pipeline run in real-time
4. When exploitation succeeds, it stops and shows results

**Supported exploits:**
- EternalBlue (MS17-010)
- vsftpd 2.3.4 Backdoor
- Apache Struts 2 (CVE-2017-5638)
- ShellShock (CVE-2014-6271)
- Samba CVE-2017-7494
- Tomcat Manager Deploy
- SSH/MySQL/FTP Brute Force
- RDP MS12-020
- Heartbleed (CVE-2014-0160)
- And more via nmap scripts + nuclei

### Network Scan
- Ping scan (`-sn`) - Host discovery only
- SYN scan (`-sS`) - Stealth scan
- TCP Connect (`-sT`) - Full connection
- UDP scan (`-sU`) - UDP ports
- Full scan (`-A`) - OS detection + version + scripts

### Port Scanner
- Common 1000 ports (default)
- Top 100/50 ports
- Full 65535 ports
- Custom port specification
- Masscan fast mode (all 65535 in ~30s)
- Service detection (`-sV`)
- Default scripts (`-sC`)

### Web Explorer
- **WhatWeb** - Technology fingerprinting
- **Gobuster** - Directory brute-force
- **Nikto** - Web server scanner
- **SQLMap** - SQL injection testing
- **FFuf** - Web fuzzing
- **Dirsearch** - Directory discovery
- **Nuclei** - Vulnerability scanning
- **Subfinder** - Subdomain enumeration

### Exploits
- EternalBlue (MS17-010)
- vsftpd 2.3.4 Backdoor
- Apache Struts 2 (CVE-2017-5638)
- Tomcat Manager brute-force
- Samba CVE-2017-7494
- WordPress XML-RPC brute-force
- SMB vulnerability scan
- SSH audit
- FTP anonymous detection
- HTTP PUT method detection

### Post-Exploitation
- SystemInfo (OS, kernel)
- Whoami (current user, UID/GID)
- Processes (top CPU consumers)
- HashDump (password hashes)
- Network (listening services)

### Password Attack
- SSH brute-force
- FTP brute-force
- HTTP form brute-force
- SMB brute-force
- RDP brute-force
- MySQL brute-force

### Reports
- Full report (complete findings)
- Executive report (high-level summary)
- Technical report (detailed vulnerabilities)
- Compliance report (mapping to standards)

### Settings
- Vault status and password change
- Network info display
- IP Jumper (automatic IP rotation)
- DNS configuration with presets
- MAC address randomization
- Encryption settings
- Operator info for reports
- System upgrade and backup
- Encrypted backup export
- Vault destruction

---

## Security Features

### Encryption

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-CBC |
| Key Derivation | PBKDF2-HMAC-SHA512 |
| Iterations | 1,000,000 (OWASP 2023) |
| Authentication | HMAC-SHA512 (Encrypt-then-MAC) |
| IV | 16-byte random per encryption |
| Key Size | 64 bytes (32 AES + 32 HMAC) |
| Salt | 32 bytes (random per vault) |
| Salt | 16 bytes (random per vault) |
| Key Size | 256 bits (32 bytes) |
| Library | `cryptography` (Python) |

### What Gets Encrypted

| Data | When | Where |
|------|------|-------|
| Network scan results | After each scan | `~/.blacksentinel-strike/vault/scans/` |
| Port scan results | After each scan | `~/.blacksentinel-strike/vault/scans/` |
| Web tool results | After each scan | `~/.blacksentinel-strike/vault/scans/` |
| Exploit results | After each scan | `~/.blacksentinel-strike/vault/scans/` |
| Configuration | On save | `~/.blacksentinel-strike/vault/config.enc` |
| Network metadata | On app exit | `~/.blacksentinel-strike/vault/metadata.enc` |

### Network Privacy

- **IP Jumper**: Changes your IP periodically to avoid tracking
- **MAC Randomization**: Changes hardware address to prevent device fingerprinting
- **DNS Switching**: Use privacy-focused DNS (Cloudflare, Quad9)

---

## Testing

### Test Results

```
TEST 1:  Vault initialization              [OK]
TEST 2:  Vault unlock                       [OK]
TEST 3:  Wrong password rejection           [OK]
TEST 4:  Encrypt/decrypt roundtrip          [OK]
TEST 5:  Scan result save/load              [OK]
TEST 6:  Config save/load                   [OK]
TEST 7:  Metadata save/load                 [OK]
TEST 8:  Destroy vault                      [OK]
TEST 9:  Get current IP                     [OK]
TEST 10: Get current MAC                    [OK]
TEST 11: Get interfaces                     [OK]
TEST 12: Get network info                   [OK]
TEST 13: Random MAC generation              [OK]
TEST 14: IP Jumper initialization           [OK]
TEST 15: IP Jumper start/stop               [OK]
TEST 16: ReconModule                        [OK]
TEST 17: WebExplorer                        [OK]
TEST 18: ExploitModule                      [OK]
TEST 19: BruteForceModule                   [OK]
TEST 20: PostExploitModule                  [OK]
TEST 21: ForensicModule                     [OK]
TEST 22: WirelessModule                     [OK]
TEST 23: NetworkAttackModule                [OK]
TEST 24: SocialEngineeringModule            [OK]
TEST 25: ReportModule                       [OK]
TEST 26: DarkOrangeTheme                       [OK]
TEST 27: DarkTheme                          [OK]
TEST 28: get_theme                          [OK]
TEST 29: NetworkUtils                       [OK]
TEST 30: SystemUtils                        [OK]
TEST 31: FileUtils                          [OK]
TEST 32: NmapParser                         [OK]
TEST 33: BruteForceUtils                    [OK]
TEST 34: ExploitUtils                       [OK]
TEST 35: Version check                      [OK]
TEST 36: Report generation                  [OK]
TEST 37: Encryption is irreversible         [OK]
TEST 38: PBKDF2 iterations >= 1000000      [OK]
TEST 39: Vault directory permissions        [OK]
TEST 40: All scan files encrypted           [OK]
TEST 41: WarExploit initialization          [OK]
TEST 42: WarExploit status                  [OK]
TEST 43: WarExploit stop                    [OK]
TEST 44: WarExploit callback                [OK]
TEST 45: WarExploit command execution       [OK]
TEST 46: WarExploit pipeline control        [OK]

ALL 46 TESTS PASSED
```

### Security Certification

- [x] AES-256 encryption verified
- [x] PBKDF2 1M iterations confirmed
- [x] Wrong password correctly rejected
- [x] File permissions set to 600 (owner only)
- [x] All scan results encrypted at rest
- [x] No hardcoded credentials or secrets
- [x] Secure key derivation (not stored plaintext)
- [x] All 16 Python files compile without errors
- [x] All 12 security tools installed and verified
- [x] Missing `time` import in wireless.py fixed
- [x] War Exploit module tested and verified

---

## File Locations

| File | Purpose |
|------|---------|
| `~/.blacksentinel-strike/vault/` | All encrypted data |
| `~/.blacksentinel-strike/vault/scans/` | Encrypted scan results |
| `~/.blacksentinel-strike/vault/config.enc` | Encrypted configuration |
| `~/.blacksentinel-strike/vault/metadata.enc` | Encrypted metadata |
| `/tmp/*.txt` | Plain-text scan outputs |
| `/tmp/report_*.txt` | Generated reports |

---

## Quick Reference

```
STARTUP:      python3 app.py
VAULT:        Create password on first run, enter on subsequent runs
SCANS:        Select module -> Configure -> Start -> Results auto-encrypted
SETTINGS:     Configure IP rotation, DNS, MAC, encryption, operator info
REPORTS:      Generate after scans -> Select sections -> Export
DEPLOY:       bash deploy.sh -> Follow prompts
DOCKER:       docker build -t blacksentinel-strike . && docker run -it blacksentinel-strike
```

---

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Always ensure you have written authorization before performing any security testing.

---

## License

All rights reserved. This software is proprietary and confidential.

---

**BlackSentinel Pentest Suite v4.0**
*Developed by BlackSentinel Strike*

---

## Before you run it

- This is a **technical preview** and the open-source edition of the product. It comes with no warranty and no service-level commitment: try it in a lab you own first.
- It is **self-hosted**. BlackSentinel does not host it for you, and paid plans are not on sale.
- Change every default credential and secret before exposing anything to a network. Never deploy with the example values from `.env.example`.
- Use it **only** on systems you own or are explicitly authorized in writing to test. See the [Acceptable Use Policy](https://blacksentinel.tech/acceptable-use/).

## Support

- Bugs and questions: [open an issue](https://github.com/BlackSentinel-Cibersecurity/blacksentinel-strike-free/issues) in this repository.
- Security reports: follow [security.txt](https://blacksentinel.tech/.well-known/security.txt). Please do not open a public issue for a vulnerability.
- Everything else: BlackSentinel-tech@protonmail.com

## License

MIT. See [LICENSE](LICENSE). The BlackSentinel name and logo are not covered by the licence.
