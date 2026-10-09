#!/bin/bash
# BlackSentinel Strike - Package Build Script
# Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
# Creates distributable packages for distribution
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "4.0.0")
BUILD_DIR="$SCRIPT_DIR/dist"
PACKAGE_NAME="blacksentinel-strike-v${VERSION}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${GREEN}[OK]${NC} $1"; }
info()  { echo -e "${CYAN}[*]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   BlackSentinel Strike - Package Builder            ║"
echo "║   Version: $VERSION                                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Parse arguments
PORTABLE=0
DOCKER=0
PYTHON=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --portable) PORTABLE=1; shift ;;
        --docker)   DOCKER=1; shift ;;
        --python)   PYTHON=1; shift ;;
        --all)      PORTABLE=1; DOCKER=1; PYTHON=1; shift ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --portable    Create portable package (tar.gz)"
            echo "  --docker      Create Docker image"
            echo "  --python      Create Python package (sdist/wheel)"
            echo "  --all         Create all package types"
            echo "  --help        Show this help"
            exit 0
            ;;
        *) warn "Unknown option: $1"; shift ;;
    esac
done

# Default to portable if no option specified
if [[ $PORTABLE -eq 0 ]] && [[ $DOCKER -eq 0 ]] && [[ $PYTHON -eq 0 ]]; then
    PORTABLE=1
fi

# Clean previous builds
info "Cleaning previous builds..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# ── Portable Package ─────────────────────────────────────────────
if [[ $PORTABLE -eq 1 ]]; then
    info "Creating portable package..."
    
    PACKAGE_DIR="$BUILD_DIR/$PACKAGE_NAME"
    mkdir -p "$PACKAGE_DIR"
    
    # Copy files
    cp "$SCRIPT_DIR/app.py" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/quick_start.py" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/requirements.txt" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/VERSION" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/README.md" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/MANUAL.md" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/MANUAL_ES.md" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/LICENSE" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/Makefile" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/deploy.sh" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/deploy_production.sh" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/deploy_kali.sh" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/start.sh" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/entrypoint.sh" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/reset_vault.sh" "$PACKAGE_DIR/"
    
    # Copy modules
    mkdir -p "$PACKAGE_DIR/modules"
    cp "$SCRIPT_DIR/modules/"*.py "$PACKAGE_DIR/modules/"
    
    # Copy tests
    mkdir -p "$PACKAGE_DIR/tests"
    cp "$SCRIPT_DIR/tests/"*.py "$PACKAGE_DIR/tests/"
    
    # Copy Docker files
    cp "$SCRIPT_DIR/Dockerfile" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/docker-compose.yml" "$PACKAGE_DIR/"
    
    # Copy config files
    cp "$SCRIPT_DIR/.env.example" "$PACKAGE_DIR/"
    cp "$SCRIPT_DIR/.bandit" "$PACKAGE_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/.flake8" "$PACKAGE_DIR/" 2>/dev/null || true
    
    # Create install script
    cat > "$PACKAGE_DIR/install.sh" << 'INSTALLER'
#!/bin/bash
# BlackSentinel Strike - Installer
# Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║   BlackSentinel Strike - Installer                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 is required. Install Python 3.10+"
    exit 1
fi

echo "[*] Python found: $(python3 --version)"

# Install dependencies
echo "[*] Installing dependencies..."
python3 -m pip install --break-system-packages -r requirements.txt

# Create vault directory
echo "[*] Creating vault directory..."
mkdir -p ~/.blacksentinel-strike/vault/scans
chmod 700 ~/.blacksentinel-strike/vault

echo ""
echo "[+] Installation complete!"
echo ""
echo "Launch: python3 app.py"
echo "Or:     bash start.sh"
INSTALLER
    chmod +x "$PACKAGE_DIR/install.sh"
    
    # Create tar.gz
    cd "$BUILD_DIR"
    tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
    cd "$SCRIPT_DIR"
    
    PACKAGE_SIZE=$(du -sh "$BUILD_DIR/${PACKAGE_NAME}.tar.gz" | cut -f1)
    log "Portable package created: dist/${PACKAGE_NAME}.tar.gz ($PACKAGE_SIZE)"
fi

# ── Docker Image ─────────────────────────────────────────────────
if [[ $DOCKER -eq 1 ]]; then
    info "Building Docker image..."
    
    docker build -t "blacksentinel-strike:${VERSION}" \
                 -t "blacksentinel-strike:latest" \
                 "$SCRIPT_DIR"
    
    # Save image
    docker save "blacksentinel-strike:${VERSION}" | \
        gzip > "$BUILD_DIR/blacksentinel-strike-docker-${VERSION}.tar.gz"
    
    DOCKER_SIZE=$(du -sh "$BUILD_DIR/blacksentinel-strike-docker-${VERSION}.tar.gz" | cut -f1)
    log "Docker image saved: dist/blacksentinel-strike-docker-${VERSION}.tar.gz ($DOCKER_SIZE)"
fi

# ── Python Package ───────────────────────────────────────────────
if [[ $PYTHON -eq 1 ]]; then
    info "Building Python package..."
    
    cd "$SCRIPT_DIR"
    
    # Create sdist and wheel
    python3 -m pip install --break-system-packages build 2>/dev/null || true
    python3 -m build --sdist --wheel --outdir "$BUILD_DIR"
    
    PYTHON_SIZE=$(du -sh "$BUILD_DIR"/*.whl 2>/dev/null | cut -f1)
    log "Python package created: dist/"
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Build Complete!                                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Output directory: dist/"
echo ""
ls -la "$BUILD_DIR"/*.tar.gz "$BUILD_DIR"/*.whl 2>/dev/null | while read line; do
    echo "    $line"
done
echo ""
echo "  Distribution methods:"
echo "    1. Send tar.gz file to users"
echo "    2. Push Docker image to registry"
echo "    3. Publish Python package to PyPI"
echo "    4. Deploy via Kubernetes/Helm"
echo ""
