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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependencies and set up virtualenv
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . /app/

# Recompile pam_ghostpot.so module inside image
RUN gcc -fPIC -shared -o /app/rootfs/debian_base/lib/x86_64-linux-gnu/security/pam_ghostpot.so /tmp/pam_ghostpot.c -lpam 2>/dev/null || true

EXPOSE 22 23 48921

ENTRYPOINT ["/app/venv/bin/python3", "/app/main.py"]
