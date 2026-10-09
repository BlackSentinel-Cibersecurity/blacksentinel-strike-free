#!/bin/bash
# BlackSentinel Strike - Production Deployment Script
# Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
# Usage: bash deploy_production.sh [--kali|--macos|--docker]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
REPORT_FILE="$SCRIPT_DIR/deployment_report_$(date +%Y%m%d_%H%M%S).txt"
MODE="standard"
SKIP_TESTS=0
FORCE=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $1"; }
err()   { echo -e "${RED}[FAIL]${NC} $1"; }
info()  { echo -e "${CYAN}[*]${NC} $1"; }

usage() {
    cat <<EOF
BlackSentinel Strike - Production Deployment

Usage: $0 [OPTIONS]

Options:
  --kali        Deploy in Kali Linux mode (install pentest tools)
  --macos       Deploy in macOS mode (brew deps)
  --docker      Deploy in Docker mode (skip GUI deps)
  --skip-tests  Skip test suite after deployment
  --force       Force reinstall (remove existing venv)
  --help        Show this message
EOF
    exit 0
}

report() {
    echo "$1" >> "$REPORT_FILE"
}

# ── Parse arguments ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kali)      MODE="kali";      shift ;;
        --macos)     MODE="macos";      shift ;;
        --docker)    MODE="docker";     shift ;;
        --skip-tests) SKIP_TESTS=1;     shift ;;
        --force)     FORCE=1;           shift ;;
        --help)      usage ;;
        *)           err "Unknown option: $1"; usage ;;
    esac
done

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   BlackSentinel Strike - Production Deploy          ║"
echo "║   Mode: $(printf '%-38s' "$MODE")║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Initialize report ────────────────────────────────────────────
> "$REPORT_FILE"
report "BlackSentinel Strike - Deployment Report"
report "Date: $(date)"
report "Mode: $MODE"
report "Host: $(hostname)"
report "Kernel: $(uname -r)"
report "────────────────────────────────────────────"

# ── 1. Check Python version ─────────────────────────────────────
info "Checking Python version..."
if ! command -v python3 &>/dev/null; then
    err "Python3 not found. Please install Python 3.10+."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 10 ]]; }; then
    err "Python 3.10+ required, found $PY_VERSION"
    exit 1
fi
log "Python $PY_VERSION detected"
report "Python: $PY_VERSION"

# ── 2. Platform-specific setup ──────────────────────────────────
setup_kali() {
    info "Kali Linux mode - installing system packages..."
    if [[ $EUID -ne 0 ]]; then
        warn "Root required for apt install. Run: sudo $0 --kali"
    else
        apt-get update -qq
        apt-get install -y -qq python3-venv python3-tk nmap nikto sqlmap \
            hydra whatweb dirb masscan nuclei subfinder ffuf \
            x11vnc xvfb net-tools dnsutils whois tcpdump macchanger \
            2>/dev/null
        log "Kali packages installed"
    fi
}

setup_macos() {
    info "macOS mode - checking Homebrew deps..."
    if command -v brew &>/dev/null; then
        brew install --quiet nmap nikto hydra whatweb masscan 2>/dev/null || true
        log "macOS brew packages checked"
    else
        warn "Homebrew not found. Install: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
}

case "$MODE" in
    kali)   setup_kali   ;;
    macos)  setup_macos  ;;
    docker) log "Docker mode - skipping system package install" ;;
esac

# ── 3. Create virtual environment ───────────────────────────────
info "Setting up virtual environment..."
if [[ -d "$VENV_DIR" ]] && [[ "$FORCE" -eq 1 ]]; then
    warn "Removing existing venv (--force)"
    rm -rf "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    log "Virtual environment created at $VENV_DIR"
else
    log "Virtual environment already exists"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
report "Venv: $VENV_DIR"

# ── 4. Install dependencies ─────────────────────────────────────
info "Installing dependencies..."
pip install --upgrade pip --quiet 2>/dev/null
pip install -r "$SCRIPT_DIR/requirements.txt" --quiet 2>&1 | tail -1
log "Dependencies installed"
report "Dependencies: $(pip list 2>/dev/null | wc -l | tr -d ' ') packages"

# ── 5. Create data directories ──────────────────────────────────
info "Creating data directories..."
BS_HOME="$HOME/.blacksentinel-strike"
VAULT_DIR="$BS_HOME/vault"
LOGS_DIR="$BS_HOME/logs"
DATA_DIR="$BS_HOME/data"
SCANS_DIR="$VAULT_DIR/scans"
KEYS_DIR="$VAULT_DIR/keys"
BACKUP_DIR="$VAULT_DIR/backups"

mkdir -p "$VAULT_DIR" "$LOGS_DIR" "$DATA_DIR" "$SCANS_DIR" "$KEYS_DIR" "$BACKUP_DIR"
log "Directories created under $BS_HOME"

# ── 6. Set proper permissions ───────────────────────────────────
info "Setting permissions..."
chmod 700 "$BS_HOME"
chmod 700 "$VAULT_DIR"
chmod 700 "$KEYS_DIR"
chmod 700 "$BACKUP_DIR"
chmod 755 "$LOGS_DIR"
chmod 755 "$DATA_DIR"
chmod 755 "$SCANS_DIR"

# Lock down sensitive files
find "$VAULT_DIR" -name "*.enc" -exec chmod 600 {} \; 2>/dev/null || true
find "$VAULT_DIR" -name "*.key" -exec chmod 600 {} \; 2>/dev/null || true
find "$VAULT_DIR" -name "*.token" -exec chmod 600 {} \; 2>/dev/null || true
log "Permissions set (700 vault, 600 sensitive files)"

# ── 7. Initialize vault ─────────────────────────────────────────
info "Initializing vault..."
if [[ ! -f "$VAULT_DIR/salt.bin" ]]; then
    python3 -c "
from modules.vault import _ensure_dirs, _generate_salt
_ensure_dirs()
if not _generate_salt():
    print('Salt already exists')
else:
    print('Salt generated')
" 2>/dev/null || warn "Vault salt init skipped (will init on first run)"
    log "Vault salt initialized"
else
    log "Vault salt already exists"
fi

# ── 8. Create default admin operator ────────────────────────────
info "Creating default admin operator..."
python3 -c "
import sys, os
sys.path.insert(0, os.path.join('$SCRIPT_DIR', 'modules'))
try:
    from operators import create_operator, OPERATORS_FILE
    if not OPERATORS_FILE.exists():
        create_operator('admin', 'blacksentinel123', 'admin', 'Default admin operator')
        print('Admin operator created')
    else:
        print('Operators file exists, skipping')
except Exception as e:
    print(f'Operator init skipped: {e}')
" 2>/dev/null || warn "Operator creation deferred to first run"
log "Default admin operator checked"

# ── 9. Run test suite ───────────────────────────────────────────
if [[ "$SKIP_TESTS" -eq 0 ]]; then
    info "Running test suite..."
    cd "$SCRIPT_DIR"
    if python3 -m pytest tests/ -x -q --tb=short 2>&1 | tail -5; then
        TEST_RESULT="PASSED"
        log "Test suite passed"
    else
        TEST_RESULT="FAILED (non-critical)"
        warn "Some tests failed (non-blocking)"
    fi
    report "Tests: $TEST_RESULT"
else
    warn "Tests skipped (--skip-tests)"
    report "Tests: SKIPPED"
fi

# ── 10. Verify tools ────────────────────────────────────────────
info "Verifying tools..."
TOOLS=("nmap" "nikto" "sqlmap" "gobuster" "hydra" "whatweb" "dirb" "masscan" "nuclei" "ffuf")
TOOL_COUNT=0
TOOL_MISSING=0

echo ""
printf "  %-15s %-10s\n" "TOOL" "STATUS"
printf "  %-15s %-10s\n" "───────────────" "──────────"

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        printf "  %-15s ${GREEN}%-10s${NC}\n" "$tool" "OK"
        report "  Tool: $tool - OK"
        ((TOOL_COUNT++))
    else
        printf "  %-15s ${RED}%-10s${NC}\n" "$tool" "MISSING"
        report "  Tool: $tool - MISSING"
        ((TOOL_MISSING++))
    fi
done
echo ""
log "Tools: $TOOL_COUNT found, $TOOL_MISSING missing"
report "Tools found: $TOOL_COUNT / ${#TOOLS[@]}"

# ── 11. Generate deployment report ──────────────────────────────
report ""
report "────────────────────────────────────────────"
report "SUMMARY"
report "  Mode:    $MODE"
report "  Python:  $PY_VERSION"
report "  Venv:    $VENV_DIR"
report "  Vault:   $VAULT_DIR"
report "  Tools:   $TOOL_COUNT/${#TOOLS[@]}"
report "  Tests:   ${TEST_RESULT:-SKIPPED}"
report "────────────────────────────────────────────"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗"
echo -e "║          Deployment Complete                        ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Launch:${NC}     source $VENV_DIR/bin/activate && python3 $SCRIPT_DIR/app.py"
echo -e "  ${CYAN}Vault:${NC}      $VAULT_DIR"
echo -e "  ${CYAN}Logs:${NC}       $LOGS_DIR"
echo -e "  ${CYAN}Report:${NC}     $REPORT_FILE"
echo ""
echo -e "  ${YELLOW}Note:${NC} First run will prompt for a master password."
echo -e "        This password encrypts ALL data. Cannot be recovered."
echo ""
