#!/bin/bash
# BlackSentinel Strike - Kali Linux Deployment
# Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
# Run with: sudo bash deploy_kali.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${RED}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   BLACKSENTINEL STRIKE v4.0 - KALI          ║"
echo "  ║   Deployment Script                          ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Run with sudo: sudo bash deploy_kali.sh${NC}"
    exit 1
fi

# Check Kali
if ! grep -qi kali /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}[!] Not running on Kali Linux. Proceeding anyway...${NC}"
fi

# Check Python
echo -e "\n${YELLOW}[*] Checking Python 3...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Installing...${NC}"
    apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv
fi
echo -e "${GREEN}[OK] $(python3 --version)${NC}"

# Install pip packages
echo -e "\n${YELLOW}[*] Installing Python dependencies...${NC}"
python3 -m pip install --break-system-packages -r "$SCRIPT_DIR/requirements.txt" 2>&1 | tail -3

# Install pentest tools
echo -e "\n${YELLOW}[*] Installing pentest tools via apt...${NC}"
TOOLS=(
    "nmap"
    "masscan"
    "nikto"
    "sqlmap"
    "hydra"
    "dirb"
    "whatweb"
    "gobuster"
    "curl"
    "wget"
    "net-tools"
    "iproute2"
    "macchanger"
    "aircrack-ng"
    "hashcat"
    "john"
    "enum4linux"
    "smbclient"
    "snmpcheck"
    "redis-tools"
    "mongodb-clients"
    "mysql-client"
    "postgresql-client"
    "dnsutils"
    "whois"
    "host"
    "tcpdump"
    "wireshark-common"
    "ettercap-text-only"
    "responder"
    "burpsuite"
    "metasploit-framework"
    "set"
    "searchsploit"
    "exploitdb"
)

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null || dpkg -l | grep -q "^ii.*$tool" 2>/dev/null; then
        echo -e "  ${GREEN}[OK] $tool${NC}"
    else
        echo -e "  ${YELLOW}[*] Installing $tool...${NC}"
        apt-get install -y -qq "$tool" 2>/dev/null || echo -e "  ${RED}[!] $tool not available${NC}"
    fi
done

# Install Go tools (nuclei, subfinder, httpx, ffuf, dirsearch)
echo -e "\n${YELLOW}[*] Installing Go-based tools...${NC}"
if command -v go &> /dev/null; then
    GOBIN=$(go env GOPATH)/bin
    export PATH="$PATH:$GOBIN"

    for pkg in "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" \
               "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" \
               "github.com/projectdiscovery/httpx/cmd/httpx" \
               "github.com/ffuf/ffuf/v2"; do
        tool=$(basename "$pkg" | sed 's|/cmd/.*||')
        if ! command -v "$tool" &> /dev/null; then
            echo -e "  ${YELLOW}[*] go install $pkg${NC}"
            go install "$pkg@latest" 2>/dev/null || echo -e "  ${RED}[!] Failed: $tool${NC}"
        else
            echo -e "  ${GREEN}[OK] $tool${NC}"
        fi
    done

    # Dirsearch (pip)
    if ! command -v dirsearch &> /dev/null; then
        python3 -m pip install --break-system-packages dirsearch 2>/dev/null || true
    fi
else
    echo -e "${YELLOW}[!] Go not found. Installing...${NC}"
    apt-get install -y -qq golang-go 2>/dev/null || true
    echo -e "${YELLOW}[!] Re-run script after Go installation for nuclei, subfinder, etc.${NC}"
fi

# Wordlists
echo -e "\n${YELLOW}[*] Checking wordlists...${NC}"
if [ -d "/usr/share/wordlists" ]; then
    echo -e "${GREEN}[OK] /usr/share/wordlists/ exists${NC}"
    ls /usr/share/wordlists/ | head -10 | while read f; do
        echo -e "  - $f"
    done
else
    apt-get install -y -qq wordlists 2>/dev/null || true
fi

# SecLists
if [ ! -d "/usr/share/seclists" ]; then
    echo -e "${YELLOW}[*] Installing SecLists...${NC}"
    apt-get install -y -qq seclists 2>/dev/null || true
fi

# Create vault directory
echo -e "\n${YELLOW}[*] Creating vault directory...${NC}"
mkdir -p /root/.blacksentinel-strike/vault/scans
chmod 700 /root/.blacksentinel-strike/vault
echo -e "${GREEN}[OK] /root/.blacksentinel-strike/vault/ created${NC}"

# Version
echo "4.0.0" > "$SCRIPT_DIR/VERSION"

# Create launcher
cat > "$SCRIPT_DIR/launch.sh" << 'LAUNCHER'
#!/bin/bash
cd "$(dirname "$0")"
python3 app.py "$@"
LAUNCHER
chmod +x "$SCRIPT_DIR/launch.sh"

# Desktop entry
cat > /root/Desktop/blacksentinel-strike.desktop << 'DESKTOP'
[Desktop Entry]
Name=BlackSentinel Strike
Comment=Professional Penetration Testing Framework
Exec=bash -c 'cd /opt/blacksentinel-strike && python3 app.py'
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=Security;
DESKTOP
chmod +x /root/Desktop/blacksentinel-strike.desktop 2>/dev/null || true

# Final summary
echo -e "\n${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   DEPLOYMENT COMPLETE!                       ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${CYAN}Launch:${NC}  bash $SCRIPT_DIR/launch.sh"
echo -e "  ${CYAN}Or:${NC}      python3 $SCRIPT_DIR/app.py"
echo ""
echo -e "  ${CYAN}Vault:${NC}   /root/.blacksentinel-strike/vault/"
echo -e "  ${CYAN}Scans:${NC}   /root/.blacksentinel-strike/vault/scans/"
echo -e "  ${CYAN}Config:${NC}  /root/.blacksentinel-strike/vault/config.enc"
echo ""
echo -e "  ${YELLOW}First run will prompt for a master password.${NC}"
echo -e "  ${YELLOW}This password encrypts ALL data. Cannot be recovered.${NC}"
echo ""
