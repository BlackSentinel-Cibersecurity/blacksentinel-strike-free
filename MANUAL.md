# BlackSentinel Pentest Suite v4.0 - Complete System Manual

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Installation](#3-installation)
4. [First Run & Vault Setup](#4-first-run--vault-setup)
5. [Dashboard](#5-dashboard)
6. [Network Scan](#6-network-scan)
7. [Port Scanner](#7-port-scanner)
8. [Web Explorer](#8-web-explorer)
9. [Exploits](#9-exploits)
10. [Post-Exploitation](#10-post-exploitation)
11. [Password Attack](#11-password-attack)
12. [Reports](#12-reports)
13. [Settings](#13-settings)
14. [Security & Encryption](#14-security--encryption)
15. [Troubleshooting](#15-troubleshooting)
16. [War Exploit](#16-war-exploit)
17. [Wireless Attacks](#17-wireless-attacks)
18. [Network Attacks](#18-network-attacks)
19. [Forensic Analysis](#19-forensic-analysis)
20. [Social Engineering](#20-social-engineering)
21. [Operator Profiles](#21-operator-profiles)
22. [Scope Authorization](#22-scope-authorization)
23. [Audit Logging](#23-audit-logging)
24. [Notifications](#24-notifications)
25. [Rate Limiting & Stealth](#25-rate-limiting--stealth)
26. [Database & History](#26-database--history)
27. [CI/CD & Deployment](#27-cicd--deployment)
28. [Testing](#28-testing)
29. [Wordlists](#29-wordlists)

---

## 1. System Overview

### What is BlackSentinel Pentest Suite?

BlackSentinel Pentest Suite is an all-in-one penetration testing platform designed for authorized security professionals. It provides a unified GUI interface that integrates industry-standard security tools (nmap, hydra, nikto, sqlmap, nuclei, masscan, etc.) with built-in AES-256 encryption to protect all scan data and operator metadata.

### What does it do?

The system performs:

- **Network Discovery**: Find live hosts on a target network using ping, SYN, and TCP connect scans
- **Port Scanning**: Identify open ports and running services on target systems (from common 1000 ports to full 65535)
- **Web Application Reconnaissance**: Fingerprint web servers, discover directories, test for SQL injection, scan for vulnerabilities
- **Exploitation Framework**: Run nmap vulnerability scripts against known CVEs (EternalBlue, vsftpd, Struts2, etc.)
- **Post-Exploitation**: Enumerate compromised systems (users, processes, network connections, password hashes)
- **Password Attacks**: Brute-force SSH, FTP, HTTP, SMB, RDP, MySQL using hydra with configurable wordlists
- **Reporting**: Generate structured penetration test reports with executive summary, methodology, findings, and recommendations

### How does it work?

1. You launch the application (Python/CustomTkinter GUI)
2. The system prompts you to create or unlock an encrypted vault (AES-256)
3. You select a module from the sidebar (Network Scan, Port Scanner, etc.)
4. You configure the target and scan parameters
5. The system executes the underlying tool (nmap, hydra, etc.) in a background thread
6. Results stream in real-time to the output console
7. All results are automatically encrypted and saved to `~/.blacksentinel-strike/vault/scans/`
8. You can generate reports from the collected data

### Why does it exist?

- **Centralized workflow**: Instead of running 12+ tools from separate terminals, everything is in one place
- **Data protection**: All scan results and operator metadata are encrypted at rest with AES-256
- **Audit trail**: Every scan is timestamped and encrypted, creating a tamper-proof record
- **Productivity**: Real-time output streaming, one-click tool execution, automated report generation
- **Deployment ready**: Can be installed on company servers for team use with Docker

### Who is it for?

Authorized penetration testers, red team operators, and security auditors who need to perform合法 security assessments on systems they have written authorization to test.

---

## 2. Architecture

```
blacksentinel-strike/
├── app.py                    # Main GUI application (1500+ lines)
├── VERSION                   # Current version (4.0.0)
├── requirements.txt          # Python dependencies
├── deploy.sh                 # Automated deployment script
├── Dockerfile                # Docker deployment
├── Makefile                  # Build, test, deploy targets
├── docker-compose.yml        # Multi-service deployment
├── .github/workflows/
│   ├── ci.yml                # CI pipeline (lint, test, build)
│   ├── release.yml           # Release automation
│   └── schedule.yml          # Scheduled security scans
├── tests/
│   ├── conftest.py           # Pytest fixtures
│   ├── test_vault.py         # Encryption tests
│   ├── test_network.py       # Network module tests
│   ├── test_web.py           # Web module tests
│   ├── test_exploits.py      # Exploit module tests
│   ├── test_war_exploit.py   # War exploit tests
│   ├── test_wireless.py      # Wireless module tests
│   ├── test_network_attacks.py  # Network attack tests
│   ├── test_forensic.py      # Forensic module tests
│   ├── test_social_engineering.py  # Social engineering tests
│   ├── test_operators.py     # Operator profile tests
│   ├── test_scope.py         # Scope authorization tests
│   ├── test_audit_log.py     # Audit logging tests
│   ├── test_notifications.py # Notification tests
│   ├── test_throttle.py      # Rate limiting tests
│   ├── test_stealth.py       # Stealth mode tests
│   ├── test_database.py      # Database tests
│   └── test_wordlists.py     # Wordlist tests
├── MANUAL.md                 # This manual
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
    ├── war_exploit.py        # Automated multi-vector attack system
    ├── forensic.py           # Forensic analysis
    ├── wireless.py           # Wireless network attacks
    ├── network_attacks.py    # Network-level attacks
    ├── social_engineering.py # Social engineering tools
    ├── reports.py            # Report generation
    ├── themes.py             # UI theme definitions
    ├── utils.py              # Shared utilities
    ├── database.py           # SQLite encrypted persistent storage
    ├── audit_log.py          # Persistent audit logging with rotation
    ├── operators.py          # Operator profiles, roles, permissions
    ├── scope.py              # Target authorization and exclusions
    ├── notifications.py      # Email and webhook alert system
    ├── throttle.py           # Rate limiting with sliding window
    └── stealth.py            # Stealth modes and decoy management
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

## 3. Installation

### Prerequisites

- macOS (tested on Apple Silicon) or Linux
- Python 3.10+
- Homebrew (macOS) or apt (Linux)
- Internet connection (for initial tool installation)

### Step-by-Step Installation

#### Step 1: Clone or download the project

```bash
cd ~/hacks
# If using git:
git clone <repository-url> pentest-gui
# Or copy the pentest-gui folder manually
cd pentest-gui
```

#### Step 2: Run the deployment script

```bash
bash deploy.sh
```

This script will:
- Check Python version
- Install pip if missing
- Install Python dependencies (customtkinter, psutil, requests, python-nmap, cryptography)
- Check/install security tools (nmap, hydra, nikto, etc.)
- Create the vault directory (`~/.blacksentinel-strike/vault/`)
- Create a launcher script

#### Step 3: Install via Makefile (recommended)

```bash
# Full install: dependencies + tools + vault setup
make install

# Deploy for production (Docker Compose)
make deploy

# Other useful targets:
make test          # Run full test suite (139 tests)
make lint          # Run linters
make typecheck     # Run type checking
make clean         # Remove build artifacts
make backup        # Backup vault and config
make docker-build  # Build Docker image
make docker-up     # Start with docker-compose
make docker-down   # Stop containers
```

#### Step 4: Install security tools manually (if deploy.sh misses any)

```bash
# macOS (Homebrew)
brew install nmap hydra nikto sqlmap gobuster masscan nuclei subfinder httpx ffuf dirsearch

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
mkdir -p ~/.blacksentinel-strike/wordlists
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    | tee ~/.blacksentinel-strike/wordlists/common.txt > /dev/null
```

#### Step 5: Install Python dependencies (if not done by deploy.sh)

```bash
pip3 install --break-system-packages -r requirements.txt
```

#### Step 6: Verify installation

```bash
# Check all tools are installed
for tool in nmap nikto sqlmap gobuster hydra whatweb masscan nuclei subfinder httpx ffuf dirsearch; do
    if command -v $tool >/dev/null 2>&1; then
        echo "[OK] $tool"
    else
        echo "[--] $tool NOT INSTALLED"
    fi
done

# Check Python packages
python3 -c "import customtkinter, psutil, requests, nmap, cryptography; print('All Python packages OK')"
```

#### Step 7: Launch the application

```bash
python3 app.py
# Or use the launcher:
bash launch.sh
```

### Docker Installation (Server Deployment)

```bash
# Build
docker build -t blacksentinel-strike .

# Run (with display forwarding for GUI)
docker run -it --net=host -e DISPLAY=$DISPLAY blacksentinel-strike

# Or run headless and access via VNC
docker run -it -p 5900:5900 blacksentinel-strike

# Production with docker-compose
docker-compose up -d
docker-compose logs -f
docker-compose down
```

### Verifying All Tools Work

After installation, run this verification:

```bash
python3 -c "
import shutil
tools = ['nmap','nikto','sqlmap','gobuster','hydra','whatweb','masscan','nuclei','subfinder','httpx','ffuf','dirsearch']
for t in tools:
    status = '[OK]' if shutil.which(t) else '[--]'
    print(f'{status} {t}')
"
```

Expected output: All 12 tools show `[OK]`.

---

## 4. First Run & Vault Setup

When you launch the application for the first time:

1. A dialog box appears: **"VAULT SETUP"**
2. You must create a **master password** (minimum 4 characters)
3. This password encrypts ALL data: scan results, configuration, metadata
4. **THIS PASSWORD CANNOT BE RECOVERED** - write it down somewhere safe

### What the Vault Protects

| Data Type          | Storage Location                | Encryption     |
|--------------------|---------------------------------|----------------|
| Scan results       | `~/.blacksentinel-strike/vault/scans/*.enc`  | AES-256        |
| Configuration      | `~/.blacksentinel-strike/vault/config.enc`   | AES-256        |
| Metadata (IP, MAC) | `~/.blacksentinel-strike/vault/metadata.enc` | AES-256        |
| Master key         | `~/.blacksentinel-strike/vault/master.key`   | PBKDF2-derived |
| Test token         | `~/.blacksentinel-strike/vault/test.token`   | AES-256        |

### Subsequent Runs

On subsequent launches, you'll be prompted to enter your master password to unlock the vault. All your previous scan results and settings will be restored.

---

## 5. Dashboard

The Dashboard is the first screen you see. It provides:

### Platform Card
- Shows: OS, kernel release, machine type, Python version
- Purpose: Quick system identification for documentation

### Tools Status Card
- Lists all 12 security tools with `[OK]` (installed) or `[--]` (missing) status
- Purpose: Verify tools are available before starting scans

### Network Info Card
- Shows: Hostname, Local IP
- Purpose: Identify your attacking machine's network position

### Quick Actions
- **Network Scan**: Jump to Network Scan module
- **Port Scan**: Jump to Port Scanner module
- **Web Explorer**: Jump to Web Explorer module
- **Reports**: Jump to Reports module

### System Info (Sidebar)
- Real-time CPU and RAM usage
- Updates every 2 seconds

---

## 6. Network Scan

**Purpose**: Discover live hosts on a target network.

### How It Works

1. Enter a target (IP address or CIDR range, e.g., `192.168.1.0/24`)
2. Select a scan type
3. Click **Start**
4. Results stream in real-time to the output console
5. Results are automatically encrypted and saved

### Scan Types

| Type        | Flag  | Description                                   | Speed  | Stealth |
|-------------|-------|-----------------------------------------------|--------|---------|
| Ping        | `-sn` | Host discovery only (no port scan)            | Fast   | High    |
| SYN         | `-sS` | SYN stealth scan (half-open)                  | Medium | High    |
| TCP Connect | `-sT` | Full TCP connection                           | Medium | Low     |
| UDP         | `-sU` | UDP port scan                                 | Slow   | Medium  |
| Full        | `-A`  | OS detection + version + scripts + traceroute | Slow   | Low     |

### When to Use Each Type

- **Ping**: Initial recon to find live hosts before deeper scanning
- **SYN**: Most common for port scanning - fast and stealthy
- **TCP Connect**: When SYN doesn't work (non-root or filtered networks)
- **UDP**: For services like DNS, SNMP, DHCP that run on UDP
- **Full**: Detailed fingerprinting of a specific target

### Example Targets

```
192.168.1.1           # Single IP
192.168.1.0/24        # Class C network
10.0.0.1-10.0.0.254   # IP range
scanme.nmap.org       # Nmap's test target
```

### Output

Results are saved to:
- Console output (real-time)
- `/tmp/ns_scan.txt` (plain text)
- `~/.blacksentinel-strike/vault/scans/netscan_YYYYMMDD_HHMMSS.enc` (encrypted)

---

## 7. Port Scanner

**Purpose**: Identify open ports and running services on a target system.

### How It Works

1. Enter a target (IP or hostname)
2. Select port range and options
3. Click **Start**
4. Results show open ports, services, and versions

### Port Range Options

| Option       | Description                 | Time   |
|--------------|-----------------------------|--------|
| Common 1000  | Default nmap top 1000 ports | ~10s   |
| Top 100      | Most common 1000 ports      | ~5s    |
| Top 50       | Most common 50 ports        | ~2s    |
| Full 65535   | All ports (slow)            | ~10min |
| Custom       | User-specified ports        | Varies |
| Masscan Fast | All 65535 ports via masscan | ~30s   |

### Options

- **Service detection (-sV)**: Identifies service versions (e.g., Apache 2.4.41)
- **Default scripts (-sC)**: Runs nmap default scripts for vulnerability detection

### When to Use

- **Common 1000**: Quick assessment of exposed services
- **Full 65535**: Comprehensive audit when time permits
- **Masscan Fast**: Quick full-port discovery, then follow up with nmap on found ports
- **Custom**: Target specific ports (e.g., `22,80,443,8080`)

### Example Workflow

```
1. Masscan Fast on 192.168.1.0/24 -> finds port 80 open on 192.168.1.50
2. Port Scan (Top 100 + Service detection) on 192.168.1.50 -> identifies Apache 2.4.41
3. Web Explorer on http://192.168.1.50 -> deep web app analysis
```

---

## 8. Web Explorer

**Purpose**: Analyze web applications for vulnerabilities and misconfigurations.

### Available Tools

| Tool      | Purpose                | What It Finds                      |
|-----------|------------------------|------------------------------------|
| WhatWeb   | Web fingerprinting     | Technology stack, CMS, frameworks  |
| Gobuster  | Directory brute-force  | Hidden files/directories           |
| Nikto     | Web server scanner     | Misconfigurations, dangerous files |
| SQLMap    | SQL injection          | Database injection vulnerabilities |
| FFuf      | Web fuzzing            | Hidden endpoints, parameters       |
| Dirsearch | Directory discovery    | Backup files, admin panels         |
| Nuclei    | Vulnerability scanning | Known CVEs, misconfigs             |
| Subfinder | Subdomain enumeration  | Hidden subdomains                  |

### How to Use

1. Enter the target URL (e.g., `http://192.168.1.50`)
2. Click the tool button you want to run
3. Results stream to the console
4. Run multiple tools for comprehensive coverage

### Recommended Workflow

```
1. WhatWeb        -> Identify technology stack
2. Subfinder      -> Find subdomains
3. Gobuster       -> Discover hidden directories
4. Nikto          -> Scan for misconfigurations
5. FFuf           -> Fuzz for hidden endpoints
6. SQLMap         -> Test for SQL injection
7. Nuclei         -> Scan for known vulnerabilities
```

### Tool Details

#### WhatWeb
```bash
whatweb -a 3 <url>
```
- `-a 3`: Aggression level (1=quiet, 3=aggressive)
- Finds: CMS type, JavaScript libraries, server software, plugins

#### Gobuster
```bash
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt -t 10
```
- `-w`: Wordlist path
- `-t`: Number of threads
- Finds: `/admin`, `/backup`, `/config.php`, etc.

#### Nikto
```bash
nikto -h <url>
```
- Scans: 7000+ potentially dangerous files/programs
- Checks for: Outdated software, misconfigurations, default files

#### SQLMap
```bash
sqlmap -u <url> --batch --crawl=2 --level=2
```
- `--batch`: Non-interactive mode
- `--crawl=2`: Crawl 2 levels deep
- `--level=2`: More thorough testing

#### FFuf
```bash
ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403
```
- `-mc`: Match HTTP status codes
- FUZZ keyword is replaced with wordlist entries

#### Nuclei
```bash
nuclei -u <url> -severity low,medium,high,critical
```
- `-severity`: Filter by severity level
- Uses community-curated vulnerability templates

---

## 9. Exploits

**Purpose**: Test for known vulnerabilities using nmap scripts.

### Available Exploits

| Exploit             | Target        | CVE/Description                              |
|---------------------|---------------|----------------------------------------------|
| EternalBlue         | SMB (445)     | MS17-010 - Windows SMB remote code execution |
| vsftpd 2.3.4        | FTP (21)      | Backdoor command execution                   |
| Apache Struts 2     | HTTP (8080)   | CVE-2017-5638 - RCE via content-type         |
| Tomcat Manager      | HTTP (8080)   | Brute-force manager credentials              |
| Samba CVE-2017-7494 | SMB (445)     | Remote code execution via writable share     |
| WordPress XML-RPC   | HTTP (80)     | Brute-force via XML-RPC                      |
| SMB Vuln Scan       | SMB (139,445) | All SMB vulnerability scripts                |
| SSH Audit           | SSH (22)      | Algorithm enumeration                        |
| FTP Anonymous       | FTP (21)      | Anonymous login detection                    |
| HTTP Put            | HTTP (80,443) | PUT method enabled                           |

### How It Works

1. Enter target IP
2. Select exploit type
3. Click **Execute**
4. nmap runs the corresponding script against the target
5. Results show vulnerability status

### Important Notes

- These are **detection** scripts, not exploitation tools
- They check if a vulnerability EXISTS, not actively exploit it
- Always have written authorization before running
- Results are saved to `/tmp/exploit.txt` and encrypted in the vault

---

## 10. Post-Exploitation

**Purpose**: Enumerate a compromised system after gaining access.

### Available Tools

| Tool       | Command                        | What It Shows                    |
|------------|--------------------------------|----------------------------------|
| SystemInfo | `uname -a` + `/etc/os-release` | OS version, kernel, distribution |
| Whoami     | `whoami && id && hostname`     | Current user, UID/GID, hostname  |
| Processes  | `ps aux --sort=-%cpu`          | Top CPU-consuming processes      |
| HashDump   | `cat /etc/shadow`              | Password hashes (requires root)  |
| Network    | `netstat -tuln`                | Listening network services       |

### When to Use

After gaining shell access to a target:
1. **SystemInfo**: Identify OS for further exploitation
2. **Whoami**: Determine privilege level
3. **Processes**: Find interesting running services
4. **HashDump**: Extract password hashes for offline cracking
5. **Network**: Map internal network connections

---

## 11. Password Attack

**Purpose**: Brute-force credentials using hydra.

### Supported Protocols

| Protocol | Port | Service                |
|----------|------|------------------------|
| SSH      | 22   | Secure Shell           |
| FTP      | 21   | File Transfer Protocol |
| HTTP     | 80   | Web Login Forms        |
| SMB      | 445  | Windows File Sharing   |
| RDP      | 3389 | Remote Desktop         |
| MySQL    | 3306 | MySQL Database         |

### How It Works

1. Enter target IP/hostname
2. Select protocol
3. Enter username
4. Select wordlist
5. Click **Attack**

### Wordlists

| Wordlist    | Size          | Use Case         |
|-------------|---------------|------------------|
| rockyou.txt | 14M passwords | General purpose  |
| top-20.txt  | 20 passwords  | Quick test       |
| common.txt  | 4K words      | Web directories  |
| Custom      | User-defined  | Targeted attacks |

### Hydra Command Structure

```bash
hydra -l <username> -P <wordlist> -s <port> -t 4 -f <target> <protocol>
```

- `-l`: Username
- `-P`: Password wordlist
- `-s`: Port number
- `-t`: Number of parallel tasks (4 recommended)
- `-f`: Stop on first found password

---

## 12. Reports

**Purpose**: Generate structured penetration test reports.

### Report Types

| Type        | Audience       | Content                            |
|-------------|----------------|------------------------------------|
| Full        | Technical team | Complete findings with evidence    |
| Executive   | Management     | High-level summary, risk ratings   |
| Technical   | IT staff       | Detailed vulnerabilities and fixes |
| Compliance  | Auditors       | Mapping to compliance standards    |

### Report Sections

1. **Executive Summary**: High-level overview of the assessment
2. **Methodology**: Steps followed during the test
3. **Findings**: Discovered vulnerabilities with evidence
4. **Recommendations**: How to fix each finding

### How to Generate

1. Enter project name
2. Select report type
3. Check desired sections
4. Click **Generate**
5. Report appears in the preview window
6. Saved to `/tmp/report_<name>.txt`

---

## 13. Settings

The Settings page controls all system configuration.

### Vault Status
- Shows LOCKED/UNLOCKED status
- **Change Password**: Change the master encryption password

### Current Network Info
- Displays current IP, MAC addresses, interface status
- **Refresh**: Update network information

### IP Jumper (Auto Rotation)
- **Enable IP Jumper**: Automatically change IP at intervals
- **Interval**: Seconds between rotations (default: 300)
- **Method**:
  - `dhcp`: Release and renew DHCP lease
  - `mac_rotate`: Change MAC address first, then renew DHCP
- **Interface**: Network interface to rotate (e.g., `en0`)
- **Rotate Now**: Trigger immediate rotation
- **Stop Jumper**: Stop automatic rotation

### DNS Configuration
- **Primary/Secondary DNS**: Set custom DNS servers
- **Presets**: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9), OpenDNS
- **Apply DNS**: Set the configured DNS servers
- **Restore Default**: Reset to DHCP-assigned DNS

### MAC Address Randomization
- **Randomize MAC on startup**: Automatically change MAC when app launches
- **Interface**: Which interface to randomize
- **Randomize Now**: Change MAC immediately

### Encryption Settings
- **Auto-encrypt scan results**: Automatically encrypt all scan output
- **Auto-encrypt metadata**: Encrypt network metadata on exit
- Algorithm info: AES-256-CBC, PBKDF2 1M iterations

### Operator Info
- **Company**: Your organization name (for reports)
- **Operator**: Your name (for reports)
- **Authorized Targets**: Comma-separated list of authorized targets

### System Upgrade
- **Current Version**: Displayed version number
- **Check Updates**: Query a remote server for updates
- **Install Deps**: Reinstall/update Python dependencies
- **Backup Now**: Create a backup of the application
- **View Log**: Show upgrade history
- **Update Source URL**: URL for update server
- **Apply Update**: Install update from local path

### Save/Export/Destroy
- **SAVE ALL SETTINGS**: Persist all configuration to encrypted vault
- **Export Encrypted Backup**: Export config as encrypted file
- **Destroy Vault**: Permanently delete all encrypted data (requires typing "DESTROY")

---

## 14. Security & Encryption

### Encryption Details

| Parameter      | Value                       |
|----------------|-----------------------------|
| Algorithm      | AES-256-CBC                 |
| Key Derivation | PBKDF2-HMAC-SHA512          |
| Iterations     | 1,000,000 (OWASP 2023)      |
| Salt           | 16 bytes (random per vault) |
| Key Size       | 256 bits (32 bytes)         |
| Library        | `cryptography` (Python)     |

### What Gets Encrypted

| Data                 | When             | Where                           |
|----------------------|------------------|---------------------------------|
| Network scan results | After each scan  | `~/.blacksentinel-strike/vault/scans/`       |
| Port scan results    | After each scan  | `~/.blacksentinel-strike/vault/scans/`       |
| Web tool results     | After each scan  | `~/.blacksentinel-strike/vault/scans/`       |
| Exploit results      | After each scan  | `~/.blacksentinel-strike/vault/scans/`       |
| Configuration        | On save          | `~/.blacksentinel-strike/vault/config.enc`   |
| Network metadata     | On app exit      | `~/.blacksentinel-strike/vault/metadata.enc` |
| Operator profiles    | On save          | `~/.blacksentinel-strike/operators.enc`      |
| Scope rules          | On save          | `~/.blacksentinel-strike/scope.enc`          |
| Audit logs           | Continuous       | `~/.blacksentinel-strike/logs/`              |
| SQLite database      | Continuous       | `~/.blacksentinel-strike/database.db`        |

### Security Modules

| Module             | Purpose                                | File                        |
|--------------------|----------------------------------------|-----------------------------|
| `vault.py`         | AES-256 encryption engine              | `modules/vault.py`          |
| `operators.py`     | Role-based access control              | `modules/operators.py`      |
| `scope.py`         | Target authorization enforcement       | `modules/scope.py`          |
| `audit_log.py`     | Tamper-proof audit trail               | `modules/audit_log.py`      |
| `database.py`      | Encrypted SQLite persistent storage    | `modules/database.py`       |
| `throttle.py`      | Rate limiting and throttling           | `modules/throttle.py`       |
| `stealth.py`       | Stealth modes and decoy management     | `modules/stealth.py`        |
| `notifications.py` | Alert delivery (email/webhook)         | `modules/notifications.py`  |

### Vault Security

- Master password is never stored - only the derived key is saved
- Each vault has a unique 16-byte salt
- 1,000,000 PBKDF2 iterations make brute-force extremely slow
- Test token verifies password without exposing the key
- File permissions set to 600 (owner read/write only)

### Network Privacy

- **IP Jumper**: Changes your IP periodically to avoid tracking
- **MAC Randomization**: Changes hardware address to prevent device fingerprinting
- **DNS Switching**: Use privacy-focused DNS (Cloudflare, Quad9)
- **Stealth Modes**: Configurable scan intensity from passive to aggressive
- **Decoy Traffic**: Generate fake scan traffic to confuse IDS/IPS

---

## 15. Troubleshooting

### Common Issues

#### "Vault setup failed"
- Check write permissions to `~/.blacksentinel-strike/vault/`
- Ensure sufficient disk space
- Try deleting `~/.blacksentinel-strike/vault/` and restarting

#### "Wrong password"
- Password is case-sensitive
- Minimum 4 characters
- If locked out, delete vault: `rm -rf ~/.blacksentinel-strike/vault/`

#### Tool not found `[--]`
```bash
# Install missing tool
brew install <tool-name>

# For whatweb
brew install ruby
git clone --depth 1 https://github.com/urbanadventurer/whatweb.git /opt/homebrew/opt/whatweb
```

#### Scan hangs or times out
- Target may be unreachable
- Firewall may be blocking
- Try a simpler scan type (Ping first)
- Check network connectivity

#### "Permission denied" on DNS/MAC changes
- These operations require sudo
- The app will prompt for your system password

#### GUI not displaying
```bash
# Ensure display is set (Linux)
export DISPLAY=:0

# Install XQuartz (macOS)
brew install --cask xquartz
```

### Getting Help

- Check the **Help** page in the application sidebar
- Review scan output in the **Console** at the bottom of the screen
- Check tool status on the **Dashboard**

### File Locations

| File                                 | Purpose                      |
|--------------------------------------|------------------------------|
| `~/.blacksentinel-strike/vault/`                  | All encrypted data           |
| `~/.blacksentinel-strike/vault/scans/`            | Encrypted scan results       |
| `~/.blacksentinel-strike/vault/config.enc`        | Encrypted configuration      |
| `~/.blacksentinel-strike/vault/metadata.enc`      | Encrypted metadata           |
| `~/.blacksentinel-strike/operators.enc`           | Encrypted operator profiles  |
| `~/.blacksentinel-strike/scope.enc`               | Encrypted scope rules        |
| `~/.blacksentinel-strike/database.db`             | SQLite database (encrypted)  |
| `~/.blacksentinel-strike/logs/`                   | Audit logs and rotation      |
| `~/.blacksentinel-strike/logs/audit.log`          | Primary audit log            |
| `~/.blacksentinel-strike/logs/audit.log.1`        | Rotated audit log            |
| `~/.blacksentinel-strike/wordlists/`              | Custom wordlists             |
| `~/.blacksentinel-strike/wordlists/common.txt`    | Web content discovery        |
| `~/.blacksentinel-strike/wordlists/passwords.txt` | Common passwords             |
| `~/.blacksentinel-strike/wordlists/usernames.txt` | Common usernames             |
| `/tmp/*.txt`                         | Plain-text scan outputs      |
| `/tmp/report_*.txt`                  | Generated reports            |

---

## 16. War Exploit

**Purpose**: Automated multi-vector attack system with a 131-CVE database and 7-stage exploitation pipeline.

### What It Does

War Exploit is a comprehensive exploitation engine that automatically identifies target types, maps vulnerabilities, and executes attacks in parallel. It maintains a database of 131 CVEs across 7 target categories.

### Target Types

| Type       | Description                        | Example Targets               |
|------------|------------------------------------|-------------------------------|
| Windows    | Windows systems (SMB, RDP, WMI)    | 192.168.1.10                  |
| Linux      | Linux/Unix systems (SSH, FTP)      | 10.0.0.5                      |
| Web        | Web applications (HTTP/HTTPS)      | http://target.com             |
| Cloud      | Cloud instances (AWS, Azure, GCP)  | ec2-xxx.compute.amazonaws.com |
| Firewall   | Firewalls and routers              | 192.168.1.1                   |
| Database   | Database servers (MySQL, MSSQL)    | db.internal.local             |
| Auto       | Auto-detect target type            | Any                           |

### 7-Stage Pipeline

```
Stage 1: Target Profiling     -> OS/service fingerprinting
Stage 2: CVE Mapping          -> Match CVEs to detected services
Stage 3: Vulnerability Check  -> Validate vulnerability existence
Stage 4: Exploit Selection    -> Choose optimal exploit per CVE
Stage 5: Parallel Execution   -> Run exploits concurrently
Stage 6: Result Collection    -> Aggregate findings
Stage 7: Report Generation    -> Structured output with evidence
```

### How to Use

1. Open the **War Exploit** module from the sidebar
2. Enter the target IP, range, or hostname
3. Select the target type (or choose **Auto** for automatic detection)
4. Optionally filter by CVE severity or category
5. Click **Execute Pipeline**
6. Monitor progress in the output console
7. Review results in the findings panel

### Available Options

| Option              | Description                              | Default   |
|---------------------|------------------------------------------|-----------|
| Target Type         | Windows/Linux/Web/Cloud/Firewall/DB/Auto | Auto      |
| Max CVEs            | Maximum CVEs to test per service         | 50        |
| Parallel Threads    | Number of concurrent exploit threads     | 8         |
| Timeout per CVE     | Seconds before skipping a CVE            | 30        |
| Severity Filter     | Filter CVEs by CVSS score                | All       |
| Auto-Exploit        | Attempt exploitation (not just detection)| False     |
| Retry on Fail       | Retry failed exploits once               | True      |
| Output Format       | Text, JSON, or both                      | Both      |

### Example Usage

```
Target:        192.168.1.0/24
Target Type:   Auto
Max CVEs:      50
Threads:       8
Severity:      high,critical

Result: 14 hosts scanned, 23 CVEs matched, 7 confirmed vulnerable
```

### Configuration

The CVE database is stored at `~/.blacksentinel-strike/cve_database.json` and can be updated:

```bash
# Update CVE database from remote source
python3 -m modules.war_exploit --update-db

# View loaded CVEs
python3 -m modules.war_exploit --list-cves

# Export CVE database
python3 -m modules.war_exploit --export-db /path/to/export.json
```

---

## 17. Wireless Attacks

**Purpose**: Wireless network auditing across WiFi, Bluetooth, Zigbee, and RFID protocols.

### What It Does

Provides a unified interface for wireless security testing, including WPA/WEP/WPS attacks, Bluetooth scanning, Zigbee protocol analysis, and RFID cloning.

### WiFi Attacks

| Attack           | Protocol | Description                              |
|------------------|----------|------------------------------------------|
| WPA2 Handshake   | WPA/WPA2 | Capture and crack WPA2 handshake         |
| PMKID Attack     | WPA2     | Offline PMKID hash cracking              |
| Evil Twin        | WPA2     | Rogue AP for credential capture          |
| WEP Crack        | WEP      | IV collection and key recovery           |
| WPS Pixie Dust   | WPS      | Offline WPS PIN recovery                 |
| WPS Brute Force  | WPS      | Online WPS PIN enumeration               |

### Bluetooth Attacks

| Attack              | Description                                    |
|---------------------|------------------------------------------------|
| Device Discovery    | Scan for discoverable Bluetooth devices        |
| Service Enumeration  | Identify open profiles and services           |
| Bluejacking         | Send unsolicited messages                      |
| Bluesnarfing        | Unauthorized data extraction                   |
| BLE Sniffing        | Capture BLE advertising packets                |

### Zigbee Attacks

| Attack              | Description                                    |
|---------------------|------------------------------------------------|
| Network Discovery   | Identify Zigbee networks and coordinators      |
| Frame Capture       | Sniff Zigbee communication frames              |
| Key Interception    | Capture network key during joining             |
| Replay Attack       | Replay captured Zigbee commands                |

### RFID Attacks

| Attack              | Description                                    |
|---------------------|------------------------------------------------|
| Card Cloning        | Read and duplicate RFID/NFC cards              |
| UID Emulation       | Emulate captured card UIDs                     |
| Brute Force         | Enumerate card values                          |
| Relay Attack        | Relay RFID communication over network          |

### How to Use

1. Open the **Wireless Attacks** module
2. Select the protocol (WiFi / Bluetooth / Zigbee / RFID)
3. Select the wireless interface
4. Choose the attack type
5. Configure parameters (SSID filter, channel, timeout)
6. Click **Start Attack**
7. Monitor captured data in real-time

### WiFi Attack Steps (WPA2 Handshake)

```
1. Select interface (e.g., wlan0mon in monitor mode)
2. Enable monitor mode: airmon-ng start wlan0
3. Select target network from scan results
4. Set channel (optional - auto-detect if not set)
5. Click "Capture Handshake"
6. Wait for client to connect (or deauth to force reconnection)
7. Handshake captured -> Saved to ~/.blacksentinel-strike/captures/
8. Click "Crack Handshake" -> Select wordlist -> Start cracking
```

### Available Options

| Option              | Description                              | Default              |
|---------------------|------------------------------------------|----------------------|
| Interface           | Wireless adapter to use                  | Auto-detect          |
| Channel             | Target channel (WiFi)                    | Auto                 |
| Duration            | Scan duration in seconds                 | 60                   |
| Deauth Packets      | Number of deauth packets (Evil Twin)     | 5                    |
| Wordlist            | Dictionary for offline cracking          | common.txt           |
| BPF Filter          | Berkeley Packet Filter expression        | None                 |
| Output Directory    | Where to save captures                   | ~/.blacksentinel-strike/captures/ |

### Configuration

```bash
# Enable monitor mode manually
sudo airmon-ng start wlan0

# Set interface for attacks
# In Settings -> Wireless -> Default Interface: wlan0mon

# Capture directory
~/.blacksentinel-strike/captures/
├── wpa_handshakes/
├── bluetooth_devices/
├── zigbee_frames/
└── rfid_cards/
```

---

## 18. Network Attacks

**Purpose**: Perform network-level attacks including ARP spoofing, DNS poisoning, VLAN hopping, and man-in-the-middle.

### What It Does

Provides tools for Layer 2 and Layer 3 network attacks used to test network segmentation, traffic interception, and protocol vulnerabilities.

### Available Attacks

| Attack                  | Layer | Description                                    |
|-------------------------|-------|------------------------------------------------|
| ARP Spoofing            | 2     | Poison ARP cache to redirect traffic           |
| DNS Poisoning           | 3     | Redirect DNS queries to attacker-controlled DNS|
| LLMNR/NBT-NS Poisoning  | 2     | Capture NTLM hashes on local networks          |
| WPAD Spoofing           | 3     | Serve malicious PAC files                      |
| DHCP Spoofing           | 2     | Rogue DHCP server for traffic interception     |
| VLAN Hopping            | 2     | Double-tagging or DTP negotiation attack       |
| Rogue DHCP              | 2     | Assign incorrect gateway/DNS to victims        |
| Man-in-the-Middle       | 3     | Full traffic interception and modification     |

### How to Use

1. Open the **Network Attacks** module
2. Select the attack type
3. Configure network parameters (interface, targets, gateway)
4. Enable additional options (SSL stripping, packet forwarding)
5. Click **Start Attack**
6. View intercepted data in the results panel
7. Click **Stop** to cease attack and restore network state

### ARP Spoofing Steps

```
1. Select interface (e.g., en0)
2. Set target IP range (e.g., 192.168.1.0/24)
3. Set gateway IP (e.g., 192.168.1.1)
4. Enable "Restore on Stop" (recommended)
5. Click "Start ARP Spoof"
6. Traffic is redirected through your machine
7. Use Wireshark or built-in sniffer to analyze traffic
8. Click "Stop" to restore ARP tables
```

### DNS Poisoning Steps

```
1. Select DNS poisoning attack
2. Set poison records (e.g., *.example.com -> attacker IP)
3. Set upstream DNS server (e.g., 8.8.8.8)
4. Start the rogue DNS server
5. Configure DHCP or ARP to redirect DNS traffic
6. Clients resolving domains will receive poisoned responses
```

### Available Options

| Option              | Description                              | Default        |
|---------------------|------------------------------------------|----------------|
| Interface           | Network interface to use                 | Auto-detect    |
| Target Range        | CIDR range of targets                    | 192.168.1.0/24 |
| Gateway             | Default gateway IP                       | Auto-detect    |
| Poison Targets      | Specific hosts to target                 | All            |
| Restore on Stop     | Restore ARP/DNS on attack stop           | True           |
| SSL Strip           | Attempt SSL stripping for HTTPS          | False          |
| Packet Forwarding   | Enable IP forwarding during attack       | True           |
| Log Traffic         | Capture intercepted packets to file      | True           |

### Security Notes

- **Only use on authorized networks** - unauthorized network attacks are illegal
- ARP spoofing may cause brief network disruption
- VLAN hopping requires trunk port access
- All attacks are logged to the audit trail

### Configuration

```bash
# Enable IP forwarding (required for MITM)
sudo sysctl -w net.inet.ip.forwarding=1

# Disable on stop
sudo sysctl -w net.inet.ip.forwarding=0

# Interface settings
# Settings -> Network Attacks -> Default Interface: en0
```

---

## 19. Forensic Analysis

**Purpose**: Digital forensics including disk imaging, memory analysis, steganography detection, and chain of custody.

### What It Does

Provides forensic analysis capabilities for incident response and post-breach investigations, including disk imaging, memory forensics, steganography detection, and browser/email artifact analysis.

### Available Tools

| Tool              | Description                                        |
|-------------------|----------------------------------------------------|
| Disk Imaging      | Create forensic disk images with integrity hashes  |
| Memory Forensics  | Analyze memory dumps for malware, artifacts        |
| Steganography     | Detect hidden data in images and audio files       |
| Browser Analysis  | Extract history, cookies, cache, bookmarks         |
| Email Analysis    | Parse email headers, attachments, metadata         |
| Chain of Custody  | Maintain evidence integrity with hash verification |
| File Recovery     | Recover deleted files from disk images             |
| Metadata Extract  | Extract EXIF, document metadata, timestamps        |

### How to Use

1. Open the **Forensic Analysis** module
2. Select the analysis type
3. Provide the source (disk image, memory dump, file, etc.)
4. Configure analysis parameters
5. Click **Analyze**
6. Review findings in structured output
7. Export report for chain of custody

### Disk Imaging Steps

```
1. Select "Disk Imaging"
2. Set source disk (e.g., /dev/disk2)
3. Set output path (e.g., ~/forensics/case001/disk.img)
4. Select hash algorithm (SHA-256 recommended)
5. Start imaging (progress shown in real-time)
6. On completion: SHA-256 hash computed and logged
7. Store hash in chain of custody document
```

### Memory Forensics Steps

```
1. Select "Memory Analysis"
2. Provide memory dump file (e.g., .raw, .mem, .vmem)
3. Analysis options:
   - Process list extraction
   - Network connection enumeration
   - Malware indicator scanning
   - Registry hive extraction
   - DLL/Driver listing
4. Click "Analyze"
5. View structured results
```

### Steganography Detection

```
1. Select "Steganography Check"
2. Provide suspect file (PNG, JPG, BMP, WAV, MP3)
3. Analysis includes:
   - LSB (Least Significant Bit) analysis
   - File carving for appended data
   - Statistical anomaly detection
   - Known stego-tool signature matching
4. Results show probability and extracted hidden data
```

### Chain of Custody

Every forensic analysis automatically generates a chain of custody record:

```
Case ID:     CASE-2026-001
Analyst:     operator@company.com
Date:        2026-06-23T14:30:00Z
Evidence:    disk.img
SHA-256:     a1b2c3d4e5f6...
Integrity:   VERIFIED
Action:      Disk imaging completed
Notes:       Source: /dev/disk2 (500GB SSD)
```

### Available Options

| Option              | Description                              | Default               |
|---------------------|------------------------------------------|-----------------------|
| Hash Algorithm      | Integrity verification algorithm         | SHA-256               |
| Block Size          | Imaging block size                       | 4096 bytes            |
| Skip Bad Sectors    | Skip unreadable sectors                  | False                 |
| Verbose Output      | Show detailed analysis progress          | True                  |
| Export Format       | JSON, CSV, or Markdown                   | JSON                  |
| Output Directory    | Where to save analysis results           | ~/.blacksentinel-strike/forensics/ |

### Configuration

```bash
# Forensic workspace
mkdir -p ~/.blacksentinel-strike/forensics/cases/

# Example case structure
~/.blacksentinel-strike/forensics/cases/CASE-2026-001/
├── evidence/
│   ├── disk.img
│   └── memory.raw
├── analysis/
│   ├── disk_analysis.json
│   └── memory_analysis.json
├── chain_of_custody.json
└── report.md
```

---

## 20. Social Engineering

**Purpose**: Social engineering attack simulation including phishing, vishing, smishing, USB attacks, and QR code generation.

### What It Does

Provides tools for testing human security through simulated social engineering attacks, helping organizations assess employee awareness and response to social engineering tactics.

### Available Attack Vectors

| Vector          | Description                                       |
|-----------------|---------------------------------------------------|
| Phishing Email  | 7 pre-built email templates with tracking         |
| Vishing         | Voice phishing scripts and call guides            |
| Smishing        | SMS phishing message templates                    |
| USB HID         | USB Rubber Ducky-style attack payloads            |
| QR Code         | Malicious QR code generation with URL shortening  |
| Watering Hole   | Compromise websites frequented by targets         |
| Pretexting      | Social engineering scenario scripts               |

### Phishing Templates

| Template           | Scenario                          | Tracking  |
|--------------------|-----------------------------------|-----------|
| Password Reset     | Fake IT password reset request    | Open/Click|
| Package Delivery   | Fake shipping notification        | Open/Click|
| Invoice            | Fake invoice from vendor          | Open/Click|
| IT Support         | Fake helpdesk credential request  | Open/Click|
| Social Media       | Fake social media notification    | Open/Click|
| Cloud Storage      | Fake file share invitation        | Open/Click|
| Meeting Invite     | Fake calendar invitation          | Open/Click|

### How to Use

1. Open the **Social Engineering** module
2. Select the attack vector (Email / Vishing / Smishing / USB / QR)
3. Choose a template or create a custom payload
4. Configure target details and sender information
5. Set up tracking (email opens, link clicks)
6. Click **Deploy** to launch the simulation
7. Monitor results in the tracking dashboard

### Phishing Email Steps

```
1. Select "Phishing Email"
2. Choose template (e.g., "Password Reset")
3. Configure:
   - Sender name: "IT Support"
   - Sender email: "it-support@company.com"
   - Target list: CSV with name, email, department
   - Landing page: Track opens and credential submissions
4. Preview the email
5. Click "Send Campaign"
6. Monitor opens, clicks, and submissions in real-time
7. Generate report showing click-through rates by department
```

### USB HID Attack

```
1. Select "USB HID Attack"
2. Choose payload type:
   - Credential Harvesting (keystroke injection)
   - Reverse Shell
   - Data Exfiltration
   - Custom DuckyScript
3. Select target OS (Windows/macOS/Linux)
4. Generate payload on USB device
5. When plugged into target, payload executes automatically
```

### QR Code Attack

```
1. Select "QR Code Generator"
2. Enter malicious URL (e.g., credential harvesting page)
3. Customize QR code appearance (optional)
4. Generate and download QR code
5. Print and place in target location
6. Track scans via landing page analytics
```

### Available Options

| Option              | Description                              | Default     |
|---------------------|------------------------------------------|-------------|
| Template            | Pre-built attack template                | Custom      |
| Landing Page        | Tracking page for credential capture     | Built-in    |
| URL Shortener       | Shorten tracking URLs                    | None        |
| SMTP Server         | Email delivery server                    | Configured  |
| Expiry              | Campaign expiration time                 | 7 days      |
| Notification        | Alert on credential submission           | True        |
| Report              | Auto-generate post-campaign report       | True        |

### Configuration

```bash
# SMTP settings for phishing emails
# Settings -> Social Engineering -> SMTP Server: smtp.company.com
# Settings -> Social Engineering -> SMTP Port: 587
# Settings -> Social Engineering -> From Address: it-support@company.com

# Landing page hosting
~/.blacksentinel-strike/social_engineering/
├── landing_pages/
│   ├── password_reset/
│   ├── cloud_storage/
│   └── custom/
├── templates/
│   ├── emails/
│   └── messages/
├── payloads/
│   └── usb_hid/
└── tracking/
    └── campaigns/
```

---

## 21. Operator Profiles

**Purpose**: Manage operator users, roles, and permissions for multi-user deployments.

### What It Does

Implements role-based access control (RBAC) for team deployments, allowing administrators to create operator accounts with appropriate permission levels.

### Available Roles

| Role       | Permissions                                             |
|------------|---------------------------------------------------------|
| Admin      | Full access: all modules, settings, operators, scope    |
| Lead       | All modules except operator management and scope rules  |
| Analyst    | Scan modules, reports, and findings viewing             |
| Viewer     | Read-only access to scan results and reports            |
| Auditor    | Read-only access to audit logs and compliance reports   |

### Permission Matrix

| Feature                 | Admin | Lead | Analyst | Viewer | Auditor |
|-------------------------|-------|------|---------|--------|---------|
| Network Scan            | Yes   | Yes  | Yes     | View   | View    |
| Port Scanner            | Yes   | Yes  | Yes     | View   | View    |
| Web Explorer            | Yes   | Yes  | Yes     | View   | View    |
| Exploits                | Yes   | Yes  | Yes     | View   | View    |
| War Exploit             | Yes   | Yes  | Yes     | View   | View    |
| Password Attack         | Yes   | Yes  | Yes     | View   | View    |
| Wireless Attacks        | Yes   | Yes  | Yes     | View   | View    |
| Network Attacks         | Yes   | Yes  | Yes     | View   | View    |
| Forensic Analysis       | Yes   | Yes  | Yes     | View   | View    |
| Social Engineering      | Yes   | Yes  | Yes     | View   | View    |
| Reports                 | Yes   | Yes  | Yes     | View   | View    |
| Settings                | Yes   | Yes  | Partial | No     | No      |
| Operator Management     | Yes   | No   | No      | No     | No      |
| Scope Authorization     | Yes   | Yes  | No      | No     | No      |
| Audit Logs              | Yes   | Yes  | No      | No     | Yes     |
| Database Management     | Yes   | Yes  | No      | No     | View    |
| System Upgrade          | Yes   | No   | No      | No     | No      |

### How to Use

1. Open **Settings** -> **Operators**
2. Click **Add Operator**
3. Enter username, email, and role
4. Generate API key (for programmatic access)
5. Set session timeout (default: 3600 seconds)
6. Click **Save**
7. Share credentials securely with the operator

### Operator Management

```
Operators Panel:
├── List Operators       -> View all operators with roles
├── Add Operator         -> Create new operator account
├── Edit Operator        -> Change role, permissions
├── Deactivate Operator  -> Disable account without deletion
├── Generate API Key     -> Create API key for programmatic access
├── Revoke API Key       -> Invalidate API key
├── View Sessions        -> Active sessions for each operator
└── Export Audit Trail   -> Download operator activity log
```

### Available Options

| Option              | Description                              | Default      |
|---------------------|------------------------------------------|--------------|
| Username            | Unique operator identifier               | Required     |
| Email               | Operator email address                   | Required     |
| Role                | Permission level                         | Analyst      |
| API Key             | Programmatic access token                | Auto-generate|
| Session Timeout     | Seconds before session expires           | 3600         |
| MFA Required        | Require multi-factor authentication      | False        |
| IP Restriction      | Limit login to specific IPs              | None         |

### Configuration

```bash
# Operator profiles are stored encrypted
~/.blacksentinel-strike/operators.enc

# API keys format
blacksentinel_api_<32-random-chars>

# Session management
# Sessions stored in memory with configurable timeout
# Expired sessions require re-authentication
```

---

## 22. Scope Authorization

**Purpose**: Define authorized targets and exclusions to ensure all testing stays within legal and contractual boundaries.

### What It Does

Enforces scope authorization by maintaining an encrypted list of authorized targets and exclusions. All scan operations are validated against the scope before execution.

### Authorization Types

| Type       | Format              | Example                              |
|------------|---------------------|--------------------------------------|
| IP Address | Single IP           | 192.168.1.10                         |
| CIDR Range | Network range       | 192.168.1.0/24                       |
| Wildcard   | Domain wildcard     | *.example.com                        |
| Domain     | Specific domain     | app.example.com                      |
| Exclude    | IP/range/domain     | 192.168.1.1 (gateway)                |
| Port Range | Specific ports      | 80,443,8080                          |

### How to Use

1. Open **Settings** -> **Scope Authorization**
2. Click **Add Target** to add authorized targets
3. Enter target (IP, CIDR, wildcard, or domain)
4. Add exclusions for out-of-scope targets
5. Set scope expiration date (optional)
6. Click **Save Scope**
7. All scan operations are now validated against scope

### Scope Validation Flow

```
User initiates scan
    ↓
Scope check: Is target authorized?
    ├── YES -> Proceed with scan
    └── NO  -> Block scan, log violation, alert admin
```

### Adding Scope Rules

```
Scope Panel:
├── Add Target
│   ├── Type: IP / CIDR / Wildcard / Domain
│   ├── Value: 192.168.1.0/24
│   └── Note: "Production network - authorized"
├── Add Exclusion
│   ├── Type: IP / CIDR / Domain
│   ├── Value: 192.168.1.1
│   └── Note: "Do not target gateway"
├── Import Scope
│   ├── CSV file with targets
│   └── One target per line
├── Export Scope
│   └── Download scope as CSV or JSON
├── Validate Scope
│   └── Test a target against current scope rules
└── View History
    └── All scope changes with timestamps
```

### Scope Validation Command

```bash
# Validate a target against scope
python3 -m modules.scope --validate 192.168.1.50

# Output:
# Target: 192.168.1.50
# Status: AUTHORIZED
# Matched rule: 192.168.1.0/24 (Production network)
# Exclusions: None

# Validate with exclusions
python3 -m modules.scope --validate 192.168.1.1

# Output:
# Target: 192.168.1.1
# Status: BLOCKED
# Matched exclusion: 192.168.1.1 (Gateway - do not target)
```

### Configuration

```bash
# Scope rules stored encrypted
~/.blacksentinel-strike/scope.enc

# Scope configuration
# Settings -> Scope -> Auto-validate: True (default)
# Settings -> Scope -> Block on violation: True (default)
# Settings -> Scope -> Alert on violation: True (default)

# Scope expiration
# Set expiration date for temporary authorizations
# Scope automatically deactivates on expiration
```

---

## 23. Audit Logging

**Purpose**: Persistent, tamper-proof audit logging with automatic rotation and structured JSON output.

### What It Does

Records all system actions, operator activities, and scan operations in a structured, tamper-proof audit log. Supports automatic log rotation to prevent disk space issues.

### What Gets Logged

| Event Type          | Description                              |
|---------------------|------------------------------------------|
| Scan Start          | Module, target, operator, timestamp       |
| Scan Complete       | Duration, findings count, status          |
| Scan Failed         | Error message, operator, timestamp        |
| Operator Login      | Username, IP, session ID                  |
| Operator Logout     | Username, session duration                |
| Scope Violation     | Blocked target, operator, rule matched    |
| Settings Change     | Setting modified, old/new values          |
| Report Generated    | Report type, sections, operator           |
| Export              | Export type, destination, operator        |
| Vault Operations    | Lock/unlock, password change              |
| System Events       | Startup, shutdown, upgrade                |

### Log Format

All log entries are JSON structured:

```json
{
  "timestamp": "2026-06-23T14:30:15.123456Z",
  "event": "scan_start",
  "operator": "admin@company.com",
  "module": "network_scan",
  "target": "192.168.1.0/24",
  "parameters": {"scan_type": "SYN", "ports": "top1000"},
  "session_id": "sess_abc123",
  "source_ip": "10.0.0.5",
  "severity": "INFO"
}
```

### How to Use

Audit logging is automatic and runs in the background. No manual activation is required.

1. View current logs: **Settings** -> **Audit Logs** -> **View**
2. Filter by event type, operator, or date range
3. Export logs: **Settings** -> **Audit Logs** -> **Export**
4. Search logs: Use the search bar to find specific events

### Log Rotation

Logs are automatically rotated based on configuration:

| Parameter       | Default    | Description                    |
|-----------------|------------|--------------------------------|
| Max File Size   | 10 MB      | Rotate when file exceeds this  |
| Max Backups     | 10         | Number of rotated files to keep|
| Rotation        | Size-based | Rotate on size threshold       |

```
~/.blacksentinel-strike/logs/
├── audit.log           # Current active log
├── audit.log.1         # Previous rotation (most recent)
├── audit.log.2         # Older rotation
├── ...
└── audit.log.10        # Oldest rotation (deleted when exceeded)
```

### Available Options

| Option              | Description                              | Default     |
|---------------------|------------------------------------------|-------------|
| Enable Logging      | Turn audit logging on/off                | True        |
| Log Level           | Minimum severity to log                  | INFO        |
| Max File Size       | Size before rotation                     | 10 MB       |
| Max Backups         | Rotated files to keep                    | 10          |
| Structured Output   | JSON format vs plain text                | JSON        |
| Include Payloads    | Log full request/response data           | False       |
| Retention Days      | Days before auto-deletion                | 365         |

### Configuration

```bash
# View audit logs
cat ~/.blacksentinel-strike/logs/audit.log | python3 -m json.tool

# Filter logs by operator
cat ~/.blacksentinel-strike/logs/audit.log | jq 'select(.operator == "admin@company.com")'

# Filter logs by event type
cat ~/.blacksentinel-strike/logs/audit.log | jq 'select(.event == "scan_start")'

# Export logs
python3 -m modules.audit_log --export --format json --output ~/export/audit_export.json

# Settings -> Audit -> Rotation: Size-based
# Settings -> Audit -> Max Size: 10MB
# Settings -> Audit -> Max Backups: 10
```

---

## 24. Notifications

**Purpose**: Send alerts via email and webhooks (Slack, Discord, Teams) when critical events occur.

### What It Does

Delivers real-time notifications when important events happen, such as high-severity findings, scope violations, scan completion, or system alerts.

### Notification Channels

| Channel       | Configuration Required                          |
|---------------|-------------------------------------------------|
| Email (SMTP)  | SMTP server, port, username, password, from     |
| Slack         | Webhook URL                                     |
| Discord       | Webhook URL                                     |
| Microsoft Teams | Webhook URL                                   |
| Custom Webhook | HTTP POST endpoint with auth token             |

### Event Triggers

| Event                | Default Severity | Description                       |
|----------------------|------------------|-----------------------------------|
| Scan Complete        | INFO             | Scan finished successfully        |
| High-Severity Finding| HIGH             | Critical or high CVSS finding     |
| Scope Violation      | CRITICAL         | Attempted out-of-scope target     |
| Scan Failed          | WARNING          | Scan error or timeout             |
| Operator Login       | INFO             | New operator session              |
| Password Change      | WARNING          | Vault password changed            |
| System Upgrade       | INFO             | System updated                    |
| Rate Limit Triggered | WARNING          | Rate limit exceeded               |
| Stealth Alert        | WARNING          | Detection risk elevated           |

### How to Use

1. Open **Settings** -> **Notifications**
2. Click **Add Channel** to configure a notification channel
3. Select channel type (Email / Slack / Discord / Teams / Custom)
4. Enter connection details (server, port, webhook URL)
5. Configure event filters (which events trigger notifications)
6. Set severity threshold (only notify for events above this level)
7. Click **Test** to verify the channel works
8. Click **Save**

### Email Configuration

```
Channel:     Email (SMTP)
SMTP Server: smtp.gmail.com
Port:        587
Use TLS:     True
Username:    alerts@company.com
Password:    **** (encrypted)
From:        BlackSentinel Alerts <alerts@company.com>
To:          security-team@company.com
```

### Webhook Configuration (Slack)

```
Channel:     Slack
Webhook URL: https://hooks.slack.com/services/T00/B00/XXXXX
Channel:     #security-alerts
Username:    BlackSentinel Bot
Icon:        :shield:
```

### Notification Format (Email)

```
Subject: [BLACKSENTINEL] CRITICAL - Scope Violation Detected

Operator: john@company.com
Event:    Scope Violation
Target:   10.0.0.1 (not authorized)
Time:     2026-06-23 14:30:15 UTC
Details:  Attempted scan on out-of-scope target.
          Scan blocked. Operator notified.
```

### Notification Format (Slack)

```json
{
  "text": "BlackSentinel Alert",
  "attachments": [{
    "color": "danger",
    "title": "Scope Violation",
    "fields": [
      {"title": "Operator", "value": "john@company.com", "short": true},
      {"title": "Target", "value": "10.0.0.1", "short": true},
      {"title": "Severity", "value": "CRITICAL", "short": true}
    ]
  }]
}
```

### Available Options

| Option              | Description                              | Default     |
|---------------------|------------------------------------------|-------------|
| Channel Name        | Identifier for this channel              | Required    |
| Channel Type        | Email / Slack / Discord / Teams / Custom | Required    |
| Severity Threshold  | Minimum severity to trigger              | HIGH        |
| Event Filter        | Which events to send                     | All         |
| Rate Limit          | Max notifications per hour               | 20          |
| Quiet Hours         | Suppress notifications during hours      | None        |
| Retry on Failure    | Retry failed sends                       | True        |

### Configuration

```bash
# Notification settings
# Settings -> Notifications -> Add Channel
# Settings -> Notifications -> Test Channel
# Settings -> Notifications -> Notification History

# Test notification
python3 -m modules.notifications --test --channel slack

# View notification history
cat ~/.blacksentinel-strike/logs/notifications.log | python3 -m json.tool
```

---

## 25. Rate Limiting & Stealth

**Purpose**: Throttle scan operations and manage stealth levels to avoid detection and network disruption.

### What It Does

Controls the intensity of scanning operations through rate limiting and configurable stealth levels, balancing thoroughness with stealth.

### Rate Limiting

| Parameter           | Description                              | Default     |
|---------------------|------------------------------------------|-------------|
| Sliding Window      | Time window for rate calculation         | 60 seconds  |
| Max Requests        | Maximum requests per window              | 100         |
| Per-Target Limit    | Max requests per individual target       | 20          |
| Burst Allowance     | Allow short bursts above limit           | 10%         |
| Cool-down Period    | Pause after rate limit hit               | 30 seconds  |

### Stealth Levels

| Level      | Name        | Description                                    |
|------------|-------------|------------------------------------------------|
| 0          | Passive     | No active scanning, only passive reconnaissance|
| 1          | Quiet       | Slow scans, low packet rate, long delays       |
| 2          | Moderate    | Balanced speed and stealth                     |
| 3          | Aggressive  | Fast scans, no delays, maximum thoroughness    |

### Stealth Level Details

#### Level 0: Passive

```
- Sniff network traffic only
- No packets sent to targets
- Read ARP tables and DNS cache
- Monitor wireless beacons
- Zero detection risk
- Use case: Initial recon without touching targets
```

#### Level 1: Quiet

```
- Scan rate: 5 packets/second
- Random delays: 500ms-2000ms between packets
- Decoys: 3-5 fake source IPs
- Fragmented packets: Enabled
- MAC randomization: Enabled
- Use case: Sensitive environments, production systems
```

#### Level 2: Moderate

```
- Scan rate: 50 packets/second
- Random delays: 100ms-500ms between packets
- Decoys: 1-3 fake source IPs
- Fragmented packets: Optional
- MAC randomization: Optional
- Use case: Standard penetration testing
```

#### Level 3: Aggressive

```
- Scan rate: 500+ packets/second
- Random delays: 0-100ms between packets
- Decoys: None (direct scanning)
- Fragmented packets: Disabled
- MAC randomization: Disabled
- Use case: Time-critical assessments, internal networks
```

### Decoy Management

```
Decoy System:
├── Auto-generate decoy IPs from target subnet
├── Use randomized source addresses
├── Mix real and fake traffic
├── Configure decoy ratio (real:fake)
└── Exclude specific IPs from decoy pool
```

### How to Use

1. Open **Settings** -> **Rate Limiting & Stealth**
2. Set the stealth level (0-3)
3. Configure rate limits (requests per second, per-target)
4. Enable/disable decoy traffic
5. Set MAC randomization preference
6. Configure jitter (random delay range)
7. Click **Save**
8. All subsequent scans use the new settings

### Available Options

| Option              | Description                              | Default     |
|---------------------|------------------------------------------|-------------|
| Stealth Level       | 0 (Passive) to 3 (Aggressive)            | 2           |
| Requests/Second     | Global scan rate limit                   | 50          |
| Per-Target Limit    | Max requests per target per minute       | 20          |
| Jitter Range        | Random delay range (ms)                  | 100-500     |
| Decoys              | Number of decoy IPs                      | 3           |
| MAC Randomization   | Change MAC before scan                   | Optional    |
| Fragment Packets    | Fragment scan packets                    | Optional    |
| Cool-down           | Pause after rate limit                   | 30s         |

### Configuration

```bash
# Stealth settings
# Settings -> Stealth -> Level: Quiet (1)
# Settings -> Stealth -> Jitter: 500-2000ms
# Settings -> Stealth -> Decoys: 5
# Settings -> Stealth -> MAC Randomization: On

# Rate limiting
# Settings -> Rate Limit -> Requests/Second: 50
# Settings -> Rate Limit -> Per-Target: 20/minute
# Settings -> Rate Limit -> Cool-down: 30s

# Manual override
python3 -m modules.stealth --level 1 --decoys 5 --jitter 500-2000
python3 -m modules.throttle --rate 25 --per-target 10
```

---

## 26. Database & History

**Purpose**: SQLite-based persistent storage for scan history, findings, statistics, and data export.

### What It Does

Provides encrypted SQLite database for storing scan results, findings history, and operational statistics. Supports full-text search, statistical analysis, and data export.

### Database Schema

```
database.db
├── scans            # All scan operations
│   ├── id           # Unique scan ID
│   ├── operator     # Operator who ran the scan
│   ├── module       # Module used (network_scan, port_scan, etc.)
│   ├── target       # Target IP/hostname/range
│   ├── start_time   # Scan start timestamp
│   ├── end_time     # Scan end timestamp
│   ├── status       # completed / failed / cancelled
│   └── results      # Encrypted JSON results
├── findings         # Individual findings
│   ├── id           # Unique finding ID
│   ├── scan_id      # Parent scan ID
│   ├── severity     # critical / high / medium / low / info
│   ├── title        # Finding title
│   ├── description  # Detailed description
│   ├── evidence     # Supporting evidence
│   ├── remediation  # Fix recommendation
│   └── timestamp    # When finding was recorded
├── operators        # Operator activity
│   ├── id           # Unique ID
│   ├── operator     # Operator email/username
│   ├── action       # Action performed
│   ├── target       # Target of action
│   └── timestamp    # When action occurred
├── statistics       # Aggregated statistics
│   ├── scans_total  # Total scans run
│   ├── findings_by_severity  # Count per severity
│   ├── targets_scanned      # Unique targets
│   └── uptime        # System uptime
└── exports          # Export history
    ├── id           # Export ID
    ├── format       # JSON / CSV / Markdown
    ├── file_path    # Export file location
    └── timestamp    # When export was created
```

### How to Use

1. Database is automatically created on first run
2. All scan results are automatically stored
3. View history: **Database** -> **History**
4. Search findings: **Database** -> **Search**
5. View statistics: **Database** -> **Statistics**
6. Export data: **Database** -> **Export**

### History Viewer

```
History Panel:
├── All Scans
│   ├── Filter by module
│   ├── Filter by operator
│   ├── Filter by date range
│   └── Filter by status
├── All Findings
│   ├── Filter by severity
│   ├── Filter by scan ID
│   └── Sort by date/severity
├── Search
│   ├── Full-text search
│   ├── Regex support
│   └── Search across all tables
└── Details
    ├── View scan details
    ├── View finding details
    └── Re-run scan
```

### Statistics Dashboard

```
Statistics:
├── Total Scans: 1,247
├── Findings: 3,891
│   ├── Critical: 12
│   ├── High: 89
│   ├── Medium: 234
│   ├── Low: 456
│   └── Info: 3,100
├── Unique Targets: 156
├── Top Modules Used:
│   ├── Network Scan: 423
│   ├── Port Scanner: 312
│   ├── Web Explorer: 287
│   └── War Exploit: 225
└── Active Operators: 8
```

### Export Options

| Format   | Description                              | Use Case           |
|----------|------------------------------------------|--------------------|
| JSON     | Structured data with all fields          | Integration, APIs  |
| CSV      | Spreadsheet-compatible format            | Excel analysis     |
| Markdown | Formatted report with tables             | Documentation      |
| PDF      | Print-ready report (via report module)   | Executive delivery |

### Available Options

| Option              | Description                              | Default     |
|---------------------|------------------------------------------|-------------|
| Auto-save           | Automatically save scan results          | True        |
| Retention Days      | Days before old records are purged       | 365         |
| Max Database Size   | Maximum database file size               | 500 MB      |
| Compression         | Compress old records                     | True        |
| Backup on Export    | Create backup before export              | True        |
| Encrypt Export      | Encrypt exported files                   | True        |

### Configuration

```bash
# Database location
~/.blacksentinel-strike/database.db

# View database size
ls -lh ~/.blacksentinel-strike/database.db

# Backup database
cp ~/.blacksentinel-strike/database.db ~/.blacksentinel-strike/database.db.backup

# Export all findings as JSON
python3 -m modules.database --export findings --format json --output ~/findings.json

# Export scan history as CSV
python3 -m modules.database --export scans --format csv --output ~/scans.csv

# Purge old records
python3 -m modules.database --purge --older-than 90d

# Database statistics
python3 -m modules.database --stats
```

---

## 27. CI/CD & Deployment

**Purpose**: Automated testing, building, and deployment pipelines using GitHub Actions, Docker Compose, and Makefile.

### What It Does

Provides continuous integration and deployment infrastructure to ensure code quality, automate testing, and streamline production deployment.

### GitHub Actions Workflows

#### ci.yml - Continuous Integration

```
Triggers:
├── Push to main/develop
├── Pull request to main
└── Manual dispatch

Jobs:
├── lint
│   ├── flake8 (Python style)
│   ├── black (formatting)
│   └── mypy (type checking)
├── test
│   ├── Unit tests (pytest)
│   ├── Integration tests
│   └── Coverage report
├── security
│   ├── Bandit (Python security)
│   ├── Safety (dependency vulnerabilities)
│   └── Trivy (container scanning)
└── build
    ├── Build Docker image
    └── Push to registry
```

#### release.yml - Release Automation

```
Triggers:
├── Git tag (v*)
└── Manual dispatch

Steps:
├── Run full test suite
├── Build release artifacts
├── Create GitHub release
├── Update VERSION file
├── Build and push Docker image
├── Notify team (Slack/email)
└── Deploy to staging (optional)
```

#### schedule.yml - Scheduled Security Scans

```
Triggers:
├── Cron: Daily at 02:00 UTC
└── Manual dispatch

Steps:
├── Run dependency vulnerability scan
├── Run full test suite
├── Check for tool updates
├── Update CVE database
├── Generate security report
└── Notify on findings
```

### Docker Compose

```yaml
# docker-compose.yml
services:
  blacksentinel:
    build: .
    ports:
      - "8080:8080"   # Web UI
      - "5900:5900"   # VNC (optional)
    volumes:
      - blacksentinel-data:/root/.blacksentinel-strike
    environment:
      - BLACKSENTINEL_MASTER_PASSWORD=${MASTER_PASSWORD}
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - blacksentinel

volumes:
  blacksentinel-data:
```

### Makefile Targets

```bash
# Installation
make install          # Full install (deps + tools + vault)
make install-deps     # Install Python dependencies only
make install-tools    # Install security tools only

# Development
make dev              # Start in development mode
make lint             # Run flake8 + black + mypy
make format           # Auto-format code with black
make typecheck        # Run mypy type checking
make test             # Run full pytest suite (139 tests)
make test-verbose     # Run tests with verbose output
make test-coverage    # Run tests with coverage report

# Building
make build            # Build Python package
make docker-build     # Build Docker image
make docker-up        # Start with docker-compose
make docker-down      # Stop containers
make docker-logs      # View container logs

# Deployment
make deploy           # Production deployment
make deploy-staging   # Deploy to staging
make backup           # Backup vault and database
make restore          # Restore from backup

# Cleanup
make clean            # Remove build artifacts
make clean-all        # Remove all generated files
make prune-images     # Remove unused Docker images
```

### How to Use

#### Setting up CI/CD

```bash
# 1. Initialize git repository
git init
git add .
git commit -m "Initial commit"

# 2. Create GitHub repository
gh repo create blacksentinel-strike --private

# 3. Push code
git remote add origin git@github.com:org/blacksentinel-strike.git
git push -u origin main

# 4. Set up GitHub Actions secrets
gh secret set BLACKSENTINEL_MASTER_PASSWORD --body "your-master-password"
gh secret set DOCKER_REGISTRY_TOKEN --body "your-registry-token"

# 5. Trigger first CI run
git push origin main
```

#### Production Deployment

```bash
# Docker Compose deployment
make deploy

# Or manual
docker-compose up -d
docker-compose ps
docker-compose logs -f blacksentinel

# Check health
curl -k https://localhost:8080/health
```

### Configuration

```bash
# Environment variables
export BLACKSENTINEL_MASTER_PASSWORD="your-secure-password"
export BLACKSENTINEL_DB_PATH="/data/database.db"
export BLACKSENTINEL_LOG_LEVEL="INFO"

# CI/CD secrets (GitHub)
BLACKSENTINEL_MASTER_PASSWORD    # Vault master password
DOCKER_REGISTRY_TOKEN      # Docker registry auth token
SLACK_WEBHOOK_URL          # Notification webhook
DEPLOY_SSH_KEY             # SSH key for deployment
```

---

## 28. Testing

**Purpose**: Automated test suite with 139 pytest tests covering all modules.

### What It Does

Provides comprehensive testing for all modules including unit tests, integration tests, and security validation tests.

### Test Coverage

| Module              | Tests | Coverage | Description                     |
|---------------------|-------|----------|---------------------------------|
| vault.py            | 12    | 94%      | Encryption, decryption, key gen |
| network_utils.py    | 8     | 87%      | IP parsing, MAC operations      |
| recon.py            | 10    | 91%      | Network scanning operations     |
| web.py              | 9     | 89%      | Web analysis tools              |
| exploits.py         | 11    | 92%      | Exploit framework               |
| bruteforce.py       | 7     | 88%      | Password attack operations      |
| war_exploit.py      | 15    | 93%      | CVE database, pipeline stages   |
| wireless.py         | 10    | 86%      | WiFi, BT, Zigbee, RFID          |
| network_attacks.py  | 8     | 85%      | ARP, DNS, VLAN attacks          |
| forensic.py         | 9     | 90%      | Disk, memory, steganography     |
| social_engineering.py | 8   | 87%      | Phishing, vishing, USB          |
| operators.py        | 10    | 95%      | RBAC, API keys, sessions        |
| scope.py            | 8     | 93%      | Authorization rules             |
| audit_log.py        | 7     | 91%      | Logging, rotation               |
| notifications.py    | 6     | 88%      | Email, webhook delivery         |
| throttle.py         | 5     | 90%      | Rate limiting                   |
| stealth.py          | 6     | 89%      | Stealth modes, decoys           |
| database.py         | 8     | 92%      | SQLite operations               |
| wordlists.py        | 4     | 95%      | Wordlist management             |
| **Total**           | **139** | **91%** | **All modules**                |

### How to Run Tests

```bash
# Run all tests
make test

# Run with verbose output
make test-verbose

# Run with coverage report
make test-coverage

# Run specific module tests
pytest tests/test_vault.py -v
pytest tests/test_war_exploit.py -v
pytest tests/test_wireless.py -v

# Run tests matching a pattern
pytest tests/ -k "test_encryption" -v

# Run tests in parallel
pytest tests/ -n auto

# Run only failed tests from last run
pytest tests/ --lf
```

### Test Structure

```
tests/
├── conftest.py              # Shared fixtures
├── test_vault.py            # 12 tests
├── test_network.py          # 8 tests
├── test_web.py              # 9 tests
├── test_exploits.py         # 11 tests
├── test_war_exploit.py      # 15 tests
├── test_wireless.py         # 10 tests
├── test_network_attacks.py  # 8 tests
├── test_forensic.py         # 9 tests
├── test_social_engineering.py  # 8 tests
├── test_operators.py        # 10 tests
├── test_scope.py            # 8 tests
├── test_audit_log.py        # 7 tests
├── test_notifications.py    # 6 tests
├── test_throttle.py         # 5 tests
├── test_stealth.py          # 6 tests
├── test_database.py         # 8 tests
└── test_wordlists.py        # 4 tests
```

### Test Configuration

```bash
# pytest.ini or pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "-v --tb=short"
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks integration tests",
    "security: marks security validation tests",
]

# Run only fast tests
pytest tests/ -m "not slow"

# Run integration tests
pytest tests/ -m "integration"
```

### Writing Tests

```python
# Example test file: tests/test_example.py
import pytest
from modules.vault import Vault

class TestVault:
    def test_encrypt_decrypt(self, tmp_path):
        """Test encryption and decryption round-trip."""
        vault = Vault(tmp_path / "test.vault")
        vault.create("test_password")
        vault.unlock("test_password")
        
        data = b"sensitive data"
        encrypted = vault.encrypt(data)
        decrypted = vault.decrypt(encrypted)
        
        assert decrypted == data
        assert encrypted != data
    
    def test_wrong_password(self, tmp_path):
        """Test that wrong password fails."""
        vault = Vault(tmp_path / "test.vault")
        vault.create("correct_password")
        
        with pytest.raises(ValueError):
            vault.unlock("wrong_password")
```

---

## 29. Wordlists

**Purpose**: Pre-configured wordlists for password attacks, directory enumeration, and fuzzing.

### Available Wordlists

| File                 | Size     | Contents                            | Use Case                |
|----------------------|----------|-------------------------------------|-------------------------|
| common.txt           | 4,614    | Common web directories              | Directory enumeration   |
| passwords.txt        | 10,000   | Most common passwords               | Password brute-force    |
| usernames.txt        | 2,500    | Common usernames                    | Username enumeration    |
| subdomains.txt       | 100,000  | Common subdomain names              | Subdomain brute-force   |
| extensions.txt       | 500      | Common file extensions              | File discovery          |
| fuzzing.txt          | 25,000   | Fuzzing payloads                    | Web fuzzing with FFuf   |

### File Locations

```
~/.blacksentinel-strike/wordlists/
├── common.txt           # 4,614 entries - Web directories
├── passwords.txt        # 10,000 entries - Common passwords
├── usernames.txt        # 2,500 entries - Common usernames
├── subdomains.txt       # 100,000 entries - Subdomains
├── extensions.txt       # 500 entries - File extensions
└── fuzzing.txt          # 25,000 entries - Fuzzing payloads
```

### How to Use

Wordlists are automatically available in all modules:

1. **Password Attack** (Hydra): Select `passwords.txt` for brute-force
2. **Web Explorer** (Gobuster/FFuf): Select `common.txt` for directories
3. **Web Explorer** (Subfinder): Select `subdomains.txt` for subdomain enumeration
4. **Port Scanner**: No wordlist needed
5. **Social Engineering**: Use `usernames.txt` for target lists

### Using Custom Wordlists

```bash
# Add custom wordlist
cp /path/to/custom.txt ~/.blacksentinel-strike/wordlists/custom.txt

# Combine wordlists
cat ~/.blacksentinel-strike/wordlists/common.txt /path/to/target-specific.txt \
    | sort -u > ~/.blacksentinel-strike/wordlists/combined.txt

# Remove duplicates
sort -u ~/.blacksentinel-strike/wordlists/common.txt > ~/.blacksentinel-strike/wordlists/common_unique.txt
```

### Wordlist Management

```bash
# List available wordlists
ls -lh ~/.blacksentinel-strike/wordlists/

# Count entries in a wordlist
wc -l ~/.blacksentinel-strike/wordlists/*.txt

# Download additional wordlists
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" \
    | tee ~/.blacksentinel-strike/wordlists/raft-large.txt > /dev/null

curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt" \
    | tee ~/.blacksentinel-strike/wordlists/top1m-passwords.txt > /dev/null

# Search wordlist for pattern
grep -i "admin" ~/.blacksentinel-strike/wordlists/usernames.txt

# Generate wordlist from target info
python3 -c "
import itertools
base = ['admin', 'test', 'user']
years = ['2024', '2025', '2026']
for b, y in itertools.product(base, years):
    print(f'{b}{y}')
" > ~/.blacksentinel-strike/wordlists/target-specific.txt
```

### Configuration

```bash
# Wordlist settings
# Settings -> Wordlists -> Default Directory: ~/.blacksentinel-strike/wordlists/
# Settings -> Wordlists -> Auto-download on first use: True

# Module-specific defaults
# Password Attack -> Default wordlist: passwords.txt
# Web Explorer -> Default wordlist: common.txt
# Subdomain Enum -> Default wordlist: subdomains.txt

# Download all SecLists wordlists (optional, ~2GB)
make download-wordlists
```

---

## Quick Reference Card

```
STARTUP:      python3 app.py
VAULT:        Create password on first run, enter on subsequent runs
SCANS:        Select module -> Configure -> Start -> Results auto-encrypted
SETTINGS:     Configure IP rotation, DNS, MAC, encryption, operator info
REPORTS:      Generate after scans -> Select sections -> Export
DEPLOY:       bash deploy.sh -> Follow prompts
DOCKER:       docker build -t blacksentinel-strike . && docker run -it blacksentinel-strike
DOCKER-COMPOSE: docker-compose up -d

WAR EXPLOIT:  Select CVE module -> Set target type -> Execute 7-stage pipeline
WIRELESS:     Select interface -> Choose attack (WPA/BT/RFID) -> Run
NET ATTACKS:  Select ARP/DNS/VLAN -> Set targets -> Enable poison
FORENSICS:    Select disk/memory/stego -> Set source -> Analyze
SOCIAL:       Select template (phish/vish/USB) -> Configure payload -> Deploy
OPERATORS:    Settings -> Operators -> Add user -> Assign role -> Save
SCOPE:        Settings -> Scope -> Add targets -> Set exclusions -> Authorize
AUDIT:        Automatic -> ~/.blacksentinel-strike/logs/audit.log
DATABASE:     Automatic -> ~/.blacksentinel-strike/database.db (findings history)
TESTS:        make test (139 tests) | pytest tests/ -v
WORDLISTS:    ~/.blacksentinel-strike/wordlists/ (6 files)
```

---

*BlackSentinel Pentest Suite v4.0.*
