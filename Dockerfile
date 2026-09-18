# Build Web Dashboard (React / Vite)

FROM node:20-alpine AS web-builder
WORKDIR /web
COPY cowrie_web/package*.json ./
RUN npm ci --prefer-offline 2>/dev/null || npm install
COPY cowrie_web/ ./
RUN npm run build

# Main Ghostpot Container

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    gcc \
    libpam0g-dev \
    openssh-server \
    telnetd \
    procps \
    iproute2 \
    iptables \
    util-linux \
    kmod \
    curl \
    ca-certificates \
    debootstrap \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependencies and set up Python virtualenv
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . /app/

# Copy built frontend assets from web-builder
COPY --from=web-builder /web/dist /app/cowrie_web/dist

# Build a pristine lightweight Debian 12 base rootfs for honeypot micro-sandboxes
RUN mkdir -p /app/rootfs/debian_base && \
    debootstrap --variant=minbase --include=openssh-server,telnetd,bash,coreutils,procps,iproute2,util-linux,iputils-ping,curl,wget,net-tools,ca-certificates \
    bookworm /app/rootfs/debian_base http://deb.debian.org/debian/ && \
    rm -rf /app/rootfs/debian_base/var/cache/apt/* /app/rootfs/debian_base/var/lib/apt/lists/* && \
    mkdir -p /app/rootfs/debian_base/run/sshd /app/rootfs/debian_base/run/systemd /app/rootfs/debian_base/dev/pts /app/rootfs/debian_base/root/.ssh && \
    echo "root:root" | chroot /app/rootfs/debian_base chpasswd && \
    echo "PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication yes\nChallengeResponseAuthentication no\nUsePAM yes" > /app/rootfs/debian_base/etc/ssh/sshd_config.d/ghostpot.conf 2>/dev/null || true

# Ensure required runtime directories exist
RUN mkdir -p /app/data /app/data/downloads /app/kernel /dev/shm/ghostpot

ENTRYPOINT ["/app/venv/bin/python3", "/app/main.py"]


