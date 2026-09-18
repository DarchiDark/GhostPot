#!/usr/bin/env bash
set -e

# Colors
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
MAGENTA="\033[1;35m"
NC="\033[0m"

echo -e "${CYAN}"
cat << "BANNER"
   ______ __                 __                __ 
  / ____// /_   ____   _____/ /_ ____   ____  / /_
 / / __ / __ \ / __ \ / ___/ __// __ \ / __ \/ __/
/ /_/ // / / // /_/ /(__  )/ /_ / /_/ // /_/ / /_  
\____//_/ /_/ \____//____/ \__// .___/ \____/ \__/ 
                              /_/                 
BANNER
echo -e "${NC}   ${YELLOW}[ Stealth MicroVM High-Interaction Honeypot Installer ]${NC}\n"

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root (or with sudo).${NC}"
    exit 1
fi

# Detect KVM
echo -e "[*] Checking hardware virtualization (KVM)..."
if [ -e /dev/kvm ]; then
    echo -e "${GREEN}[✓] KVM Hardware Acceleration is available!${NC}"
else
    echo -e "${YELLOW}[!] Warning: /dev/kvm not detected. Running in QEMU TCG software emulation mode.${NC}"
    echo -e "    (Tip: Enable Nested Virtualization in your VPS provider dashboard for maximum performance)"
fi

# Check Docker & Docker Compose
if ! command -v docker &> /dev/null; then
    echo -e "[*] Installing Docker..."
    curl -fsSL https://get.docker.com | sh
fi

# Generate Random Credentials
RANDOM_PORT=$((20000 + RANDOM % 38000))
DEFAULT_SLUG="ghost_$(openssl rand -hex 6 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 12 | head -n 1)"

echo -e "\n${CYAN}Configuration Setup${NC}"
read -p "Enable SSH Honeypot (Port 22)? [Y/n]: " RESP_SSH
RESP_SSH=${RESP_SSH:-Y}
if [[ "$RESP_SSH" =~ ^[Yy]$ ]]; then
    SSH_ENABLED=true
    read -p "SSH Listen Port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
else
    SSH_ENABLED=false
    SSH_PORT=22
fi

read -p "Enable Telnet Honeypot (Port 23)? [Y/n]: " RESP_TELNET
RESP_TELNET=${RESP_TELNET:-Y}
if [[ "$RESP_TELNET" =~ ^[Yy]$ ]]; then
    TELNET_ENABLED=true
    read -p "Telnet Listen Port [23]: " TELNET_PORT
    TELNET_PORT=${TELNET_PORT:-23}
else
    TELNET_ENABLED=false
    TELNET_PORT=23
fi

read -p "Web Panel Port [or ${RANDOM_PORT}]: " INPUT_WEB_PORT
WEB_PORT=${INPUT_WEB_PORT:-$RANDOM_PORT}

read -p "Secret Web URL Slug [or ${DEFAULT_SLUG}]: " INPUT_SLUG
SECRET_SLUG=${INPUT_SLUG:-$DEFAULT_SLUG}

echo -e "\n${CYAN}--- Network & Threat Scoring Customization ---${NC}"
echo -e "Choose Network Egress Profile (anti-heuristic evasion):"
echo -e "  1) [Recommended] Randomized Realistic Bandwidth (1.5 - 8.0 Mbps + Jitter)"
echo -e "  2) Low-Bandwidth IoT Profile (512 Kbps - 2.0 Mbps)"
echo -e "  3) High-Speed Cloud VPS Profile (10 - 50 Mbps)"
echo -e "  4) Unlimited (No traffic control)"
read -p "Select Profile [1-4, default 1]: " NET_CHOICE
NET_CHOICE=${NET_CHOICE:-1}

case "$NET_CHOICE" in
    2)
        BW_MODE="randomized"
        BW_MIN=512
        BW_MAX=2000
        BW_JITTER=25
        ;;
    3)
        BW_MODE="randomized"
        BW_MIN=10000
        BW_MAX=50000
        BW_JITTER=5
        ;;
    4)
        BW_MODE="unlimited"
        BW_MIN=0
        BW_MAX=0
        BW_JITTER=0
        ;;
    *)
        BW_MODE="randomized"
        BW_MIN=1500
        BW_MAX=8000
        BW_JITTER=15
        ;;
esac

read -p "Enable Automatic Threat-Score Sandbox Termination (Auto-Kill on scan/forkbomb)? [Y/n]: " RESP_THREAT
RESP_THREAT=${RESP_THREAT:-Y}
if [[ "$RESP_THREAT" =~ ^[Yy]$ ]]; then
    THREAT_ENABLED=true
else
    THREAT_ENABLED=false
fi

echo -e "\n${CYAN}Authentication Policy${NC}"
echo -e "Choose SSH Authentication Policy:"
echo -e "  1) [Recommended] Dynamic Simulation (High-Stealth Honeypot):"
echo -e "     - Simulates a real server: rejects the first 1-3 attempts with 'Access Denied',"
echo -e "       then accepts the next password and binds/locks it to that attacker's IP for 24h."
echo -e "  2) Capture All (Instant Entry):"
echo -e "     - Accepts any credentials on the very 1st attempt (records password & SSH keys)."
echo -e "  3) Strict Password Only:"
echo -e "     - Requires password attempts (blocks SSH public keys and None-Auth)."
echo -e "  4) Open Sandbox (Zero-Auth / Instant Entry):"
echo -e "     - Accepts everything PLUS allows direct shell access without entering any password at all (None-Auth)."
read -p "Select Auth Policy [1-4, default 1]: " AUTH_CHOICE
AUTH_CHOICE=${AUTH_CHOICE:-1}

case "$AUTH_CHOICE" in
    2)
        AUTH_MODE="accept_all"
        ALLOW_NONE=false
        ALLOW_PUBKEY=true
        REQ_PASS=true
        MIN_ATT=1
        ;;
    3)
        AUTH_MODE="accept_all"
        ALLOW_NONE=false
        ALLOW_PUBKEY=false
        REQ_PASS=true
        MIN_ATT=1
        ;;
    4)
        AUTH_MODE="accept_all"
        ALLOW_NONE=true
        ALLOW_PUBKEY=true
        REQ_PASS=false
        MIN_ATT=1
        ;;
    *)
        AUTH_MODE="dynamic"
        ALLOW_NONE=false
        ALLOW_PUBKEY=true
        REQ_PASS=true
        MIN_ATT=2
        ;;
esac

# Write config.yaml
cat << CONFIG > config.yaml
services:
  ssh:
    enabled: ${SSH_ENABLED}
    listen_port: ${SSH_PORT}
    target_port: 2222
  telnet:
    enabled: ${TELNET_ENABLED}
    listen_port: ${TELNET_PORT}
    target_port: 2323

auth:
  mode: "${AUTH_MODE}"
  allow_none_auth: ${ALLOW_NONE}
  allow_publickey: ${ALLOW_PUBKEY}
  require_password: ${REQ_PASS}
  min_attempts: ${MIN_ATT}
  max_attempts: 3
  cache_ttl_hours: 24

web:
  host: "0.0.0.0"
  port: ${WEB_PORT}
  secret_slug: "${SECRET_SLUG}"
  title: "GHOSTPOT // Honeypot Intelligence Center"

network:
  outbound_enabled: true
  block_private_subnets: true
  block_spam_ports: [25, 465, 587, 445, 139]
  bandwidth:
    mode: "${BW_MODE}"
    min_rate_kbps: ${BW_MIN}
    max_rate_kbps: ${BW_MAX}
    jitter_ms: ${BW_JITTER}
  threat_scoring:
    enabled: ${THREAT_ENABLED}
    max_score_threshold: 100
    penalty_private_lan: 40
    penalty_syn_flood: 35
    penalty_destructive_cmd: 30

vm:
  pool_size: 2
  memory_mb: 128
  vcpus: 1
  use_kvm: null
  kernel_path: "kernel/vmlinuz"
  rootfs_path: "rootfs/alpine-rootfs.raw"
  tmpfs_dir: "/dev/shm/ghostpot"

storage:
  db_path: "data/ghostpot.db"
  downloads_dir: "data/downloads"
CONFIG

mkdir -p data/downloads

echo -e "\n[*] Building and launching Ghostpot container..."
docker compose up -d --build

SERVER_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}' || echo "YOUR_SERVER_IP")

echo -e "${GREEN}  ✓ GHOSTPOT DEPLOYED SUCCESSFULLY!${NC}"
echo -e "  - SSH Honeypot:    ${CYAN}${SSH_ENABLED} (Port ${SSH_PORT})${NC}"
echo -e "  - Telnet Honeypot: ${CYAN}${TELNET_ENABLED} (Port ${TELNET_PORT})${NC}"
echo -e "  - Web Dashboard:   ${MAGENTA}http://${SERVER_IP}:${WEB_PORT}/${SECRET_SLUG}/${NC}"
echo -e "To view live logs:    ${CYAN}docker compose logs -f${NC}"
echo -e "To stop Ghostpot:     ${CYAN}docker compose down${NC}\n"
