#!/bin/bash
# BlackSentinel Strike - Docker Production Deployment
# Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="blacksentinel-strike"
CONTAINER_NAME="blacksentinel-strike-prod"
NOVNC_PORT=6080
VNC_PORT=5900
BS_HOME="$HOME/.blacksentinel-strike"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $1"; }
err()   { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info()  { echo -e "${CYAN}[*]${NC} $1"; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   BlackSentinel Strike - Docker Production Deploy   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Pre-flight checks ───────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    err "Docker not found. Install: https://docs.docker.com/get-docker/"
fi

if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon not running."
fi

# ── Create host directories ─────────────────────────────────────
info "Ensuring host directories exist..."
mkdir -p "$BS_HOME/vault/scans" \
         "$BS_HOME/vault/keys" \
         "$BS_HOME/vault/backups" \
         "$BS_HOME/logs" \
         "$BS_HOME/data"
chmod 700 "$BS_HOME" "$BS_HOME/vault"
log "Host directories ready"

# ── Build image ──────────────────────────────────────────────────
info "Building Docker image: $IMAGE_NAME..."
docker build -t "$IMAGE_NAME:latest" -t "$IMAGE_NAME:$(date +%Y%m%d)" "$SCRIPT_DIR"
log "Image built: $IMAGE_NAME:latest"

# ── Stop existing container ──────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    warn "Stopping existing container..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    log "Old container removed"
fi

# ── Load .env if present ────────────────────────────────────────
ENV_FILE=""
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    ENV_FILE="$SCRIPT_DIR/.env"
    log "Using env file: $ENV_FILE"
fi

# ── Run container ────────────────────────────────────────────────
info "Starting production container..."
DOCKER_RUN_ARGS=(
    -d
    --name "$CONTAINER_NAME"
    --restart unless-stopped
    --hostname blacksentinel-strike
    -p "$VNC_PORT:5900"
    -p "$NOVNC_PORT:6080"
    -v "$BS_HOME/vault:/root/.blacksentinel-strike/vault"
    -v "$BS_HOME/logs:/root/.blacksentinel-strike/logs"
    -v "$BS_HOME/data:/root/.blacksentinel-strike/data"
    -e PYTHONUNBUFFERED=1
    -e DISPLAY=:0
    -e VAULT_DIR=/root/.blacksentinel-strike/vault
    -e LOG_DIR=/root/.blacksentinel-strike/logs
    -e BLACKSENTINEL_MODE=production
    --cap-drop=ALL
    --cap-add=NET_RAW
    --cap-add=NET_ADMIN
    --security-opt=no-new-privileges:true
    --memory=4g
    --cpus=2
)

if [[ -n "$ENV_FILE" ]]; then
    DOCKER_RUN_ARGS+=(--env-file "$ENV_FILE")
fi

docker run "${DOCKER_RUN_ARGS[@]}" "$IMAGE_NAME:latest"
log "Container started: $CONTAINER_NAME"

# ── Wait for health check ───────────────────────────────────────
info "Waiting for container to be healthy..."
HEALTHY=0
for i in $(seq 1 30); do
    if docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null | grep -q "healthy"; then
        HEALTHY=1
        break
    fi
    sleep 2
done

if [[ "$HEALTHY" -eq 1 ]]; then
    log "Container is healthy"
else
    warn "Container health check timed out (may still be starting)"
fi

# ── Verify volumes ──────────────────────────────────────────────
info "Verifying volume mounts..."
for vol in vault logs data; do
    if docker exec "$CONTAINER_NAME" test -d "/root/.blacksentinel-strike/$vol" 2>/dev/null; then
        log "Volume /root/.blacksentinel-strike/$vol mounted"
    else
        warn "Volume /root/.blacksentinel-strike/$vol not found"
    fi
done

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗"
echo -e "║         Docker Deployment Complete                  ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Container:${NC}  $CONTAINER_NAME"
echo -e "  ${CYAN}VNC:${NC}       http://localhost:$VNC_PORT"
echo -e "  ${CYAN}noVNC:${NC}     http://localhost:$NOVNC_PORT"
echo -e "  ${CYAN}Vault:${NC}     $BS_HOME/vault (persistent)"
echo -e "  ${CYAN}Logs:${NC}      $BS_HOME/logs (persistent)"
echo ""
echo -e "  ${YELLOW}Commands:${NC}"
echo -e "    docker logs -f $CONTAINER_NAME"
echo -e "    docker exec -it $CONTAINER_NAME bash"
echo -e "    docker stop $CONTAINER_NAME"
echo ""
