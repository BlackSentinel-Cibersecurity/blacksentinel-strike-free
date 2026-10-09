#!/bin/bash
# BlackSentinel Strike - Reset Vault
# Copyright (c) 2024-2025 BlackSentinel Strike
# Deletes all encrypted data and prompts for new password on next launch
# Run with: bash reset_vault.sh

echo "============================================"
echo "  BlackSentinel Strike Vault Reset"
echo "============================================"
echo ""

VAULT_DIR="$HOME/.blacksentinel-strike/vault"

if [ ! -d "$VAULT_DIR" ]; then
    echo "[*] No vault found. Nothing to reset."
    echo "[*] App will prompt for password creation on next launch."
    exit 0
fi

echo "[*] Current vault contents:"
ls -la "$VAULT_DIR/" 2>/dev/null
echo ""

read -p "[?] Delete ALL encrypted data? (y/N): " confirm
if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    rm -rf "$VAULT_DIR"
    echo "[OK] Vault deleted."
    echo "[*] App will prompt for new password on next launch."
else
    echo "[*] Cancelled. Vault preserved."
fi
