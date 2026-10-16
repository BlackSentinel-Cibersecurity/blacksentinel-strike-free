#!/usr/bin/env python3
"""
BLACKSENTINEL STRIKE - Quick Start Launcher
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
"""

import subprocess
import sys
import os
import shutil


def check_dependencies():
    """Check all required dependencies."""
    print("=" * 60)
    print("        CHECKING DEPENDENCIES")
    print("=" * 60)

    python_deps = {
        "customtkinter": "pip3 install customtkinter",
        "psutil": "pip3 install psutil",
        "requests": "pip3 install requests",
        "cryptography": "pip3 install cryptography",
        "python_nmap": "pip3 install python-nmap",
    }

    system_tools = {
        "nmap": "brew install nmap (macOS) or apt install nmap (Linux)",
        "hydra": "brew install hydra (macOS) or apt install hydra (Linux)",
        "nikto": "brew install nikto (macOS) or apt install nikto (Linux)",
        "sqlmap": "pip3 install sqlmap or apt install sqlmap",
        "gobuster": "go install github.com/OJ/gobuster/v3@latest",
    }

    missing_python = []
    missing_tools = []

    print("\n[Python Packages]")
    for package, install_cmd in python_deps.items():
        try:
            __import__(package)
            print(f"  [OK] {package}")
        except ImportError:
            print(f"  [--] {package} NOT FOUND")
            missing_python.append((package, install_cmd))

    print("\n[System Tools]")
    for tool, install_cmd in system_tools.items():
        if shutil.which(tool):
            print(f"  [OK] {tool}")
        else:
            print(f"  [--] {tool} NOT FOUND")
            missing_tools.append((tool, install_cmd))

    return missing_python, missing_tools


def install_missing(packages, label):
    """Install missing packages."""
    if not packages:
        return

    print(f"\n{'=' * 60}")
    print(f"  INSTALLING MISSING {label}")
    print(f"{'=' * 60}")

    for package, install_cmd in packages:
        print(f"\n[*] Installing {package}...")
        try:
            subprocess.run(install_cmd, shell=True, check=True, capture_output=True, text=True)
            print(f"  [OK] {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"  [!] Failed to install {package}")
            print(f"      Manual install: {install_cmd}")


def check_root():
    """Check if running with appropriate permissions."""
    if os.name == "nt":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("\n[*] Note: Some features require Administrator privileges.")
                print("    Right-click and 'Run as Administrator' for full access.")
        except Exception:
            pass
    elif os.geteuid() != 0:
        print("\n[*] Note: Some features (MAC change, IP rotation) require root.")
        print("    Run with: sudo python3 quick_start.py")


def print_banner():
    """Print the application banner."""
    print("""
\033[38;2;255;140;0m
    ██████╗ ██╗  ██╗ █████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ██████╗
    ██╔══██╗██║  ██║██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██╔══██╗
    ██████╔╝███████║███████║███████╗██████╔╝███████║███████║██████╔╝
    ██╔═══╝ ██╔══██║██╔══██║╚════██║██╔═══╝ ██╔══██║██╔══██║██╔══██╗
    ██║     ██║  ██║██║  ██║███████║██║     ██║  ██║██║  ██║██║  ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
\033[0m
\033[38;2;204;102;0m                    BLACKSENTINEL STRIKE v4.0
\033[38;2;136;136;136m                    Penetration Testing Professional Tool
\033[0m
\033[38;2;204;102;0m    ════════════════════════════════════════════════════════
\033[0m
""")


def main():
    """Main launcher function."""
    print_banner()

    # Check dependencies
    missing_python, missing_tools = check_dependencies()

    # Offer to install missing Python packages
    if missing_python:
        response = input("\n[?] Install missing Python packages? (y/n): ")
        if response.lower() == "y":
            install_missing(missing_python, "PYTHON PACKAGES")
        else:
            print("[*] Skipping Python package installation")

    # Show missing system tools
    if missing_tools:
        print("\n[!] Missing system tools (install manually):")
        for tool, cmd in missing_tools:
            print(f"    {tool}: {cmd}")

    # Check root permissions
    check_root()

    # Launch application
    print(f"\n{'=' * 60}")
    print("        LAUNCHING BLACKSENTINEL STRIKE")
    print(f"{'=' * 60}\n")

    try:
        from app import App

        app = App()
        app.mainloop()
    except ImportError as e:
        print(f"\n[!] Error importing modules: {e}")
        print("    Make sure you are in the pentest-gui directory")
        print("    Or run: pip3 install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
