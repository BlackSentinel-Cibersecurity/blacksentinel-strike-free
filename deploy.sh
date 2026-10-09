#!/bin/bash
# BlackSentinel Strike - Deployment Script
# Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
# Run with: bash deploy.sh

set -e

echo "============================================"
echo "  BlackSentinel Strike v4.0 - Deployer"
echo "============================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check Python
echo -e "${YELLOW}[*] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Install: apt install python3 python3-pip${NC}"
    exit 1
fi
PY_VER=$(python3 --version 2>&1)
echo -e "${GREEN}[OK] $PY_VER${NC}"

# Check/Install pip
echo -e "${YELLOW}[*] Checking pip...${NC}"
if ! python3 -m pip --version &> /dev/null; then
    echo -e "${YELLOW}[*] Installing pip...${NC}"
    python3 -m ensurepip --default-pip 2>/dev/null || true
fi

# Install dependencies
echo -e "${YELLOW}[*] Installing dependencies...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -m pip install --break-system-packages -r "$SCRIPT_DIR/requirements.txt" 2>&1 | tail -1

# Check tools
echo ""
echo -e "${YELLOW}[*] Checking optional tools...${NC}"
TOOLS=("nmap" "nikto" "sqlmap" "gobuster" "hydra" "whatweb" "dirb")
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}[OK] $tool${NC}"
    else
        echo -e "  ${RED}[--] $tool (not installed)${NC}"
    fi
done

# Create vault directory
echo ""
echo -e "${YELLOW}[*] Creating vault directory...${NC}"
mkdir -p ~/.blacksentinel-strike/vault/scans
chmod 700 ~/.blacksentinel-strike/vault
echo -e "${GREEN}[OK] ~/.blacksentinel-strike/vault/ created${NC}"

# Create VERSION file
echo "4.0.0" > "$SCRIPT_DIR/VERSION"

# Create launcher
cat > "$SCRIPT_DIR/launch.sh" << 'LAUNCHER'
#!/bin/bash
cd "$(dirname "$0")"
python3 app.py "$@"
LAUNCHER
chmod +x "$SCRIPT_DIR/launch.sh"

echo ""
echo -e "${GREEN}============================================"
echo "  Deployment Complete!"
echo "============================================${NC}"
echo ""
echo "  Launch:  bash $SCRIPT_DIR/launch.sh"
echo "  Or:      python3 $SCRIPT_DIR/app.py"
echo ""
echo "  Vault:   ~/.blacksentinel-strike/vault/"
echo "  Config:  ~/.blacksentinel-strike/vault/config.enc"
echo "  Scans:   ~/.blacksentinel-strike/vault/scans/"
echo ""
echo "  First run will prompt for a master password."
echo "  This password encrypts ALL data. Cannot be recovered."
echo ""
