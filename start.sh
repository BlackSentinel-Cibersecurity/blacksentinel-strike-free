#!/bin/bash
# ══════════════════════════════════════════════════════════════
#        BLACKSENTINEL STRIKE - Launch Script
#        Copyright (c) 2024-2025 BlackSentinel Strike
# ══════════════════════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════════════"
echo "        BLACKSENTINEL STRIKE v4.0"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Starting application..."
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: Python3 is not installed"
    exit 1
fi

# Check dependencies
echo "[*] Checking dependencies..."
pip3 install customtkinter psutil requests python-nmap --quiet 2>/dev/null

# Run application
python3 /Users/mathews/hacks/pentest-gui/app.py

echo ""
echo "[*] Application closed."
