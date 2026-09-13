# 👻 Ghostpot

> **Stealth MicroVM High-Interaction Honeypot for SSH & Telnet**  
> Undetectable by port scanners, botnet fingerprinters, and anti-VM malware checks. Ephemeral in-RAM sandboxing, automatic dropped payload capture, and crawler-immune Web Intelligence Dashboard.

---

## ⚡ Key Features

- **🚀 Real Linux MicroVMs (QEMU `microvm`):** Real independent Linux kernel with native `sshd` and `telnetd`. Executes actual ELF malware binaries without Python/script emulator artifacts.
- **🛡️ Ephemeral RAM Sandboxing (CoW):** Every connection gets a fresh virtual machine running on `tmpfs` / RAM. Instant teardown and zero state persistence across sessions.
- **🦠 In-RAM Malware Artifact Extraction:** Automatically dumps files dropped by attackers (into `/tmp`, `/root`, etc.) from the CoW delta overlay before destruction, computing SHA256 hashes.
- **🕶️ Anti-Shodan / Crawler Defense:** Web panel is hosted on a configurable/random port behind a cryptographically randomized URL slug (e.g. `http://IP:48921/ghost_9f2a7b8e14/`). Standard HTTP scans to `/` or `/api/` receive silent `404 Not Found` responses.
- **🎛️ Modular Protocol Switcher:** Enable or disable SSH and Telnet independently, with custom port bindings.
- **📊 Integrated Web Intelligence Dashboard:** Native React SPA with interactive session graphs, GeoIP threat map, command timelines, top credentials, and direct malware binary downloads.

---

## 🆚 Ghostpot vs Cowrie vs Docker Containers

| Feature | Legacy Emulators (Cowrie) | Docker Honeypots | 👻 Ghostpot MicroVM |
| :--- | :---: | :---: | :---: |
| **Real Kernel & Syscalls** | ❌ (Python mock) | ⚠️ (Shared Host Kernel) | ✅ **100% Real Linux Kernel** |
| **SSH Fingerprint (HASSH)** | ❌ (Easily detected) | ⚠️ (Docker-specific) | ✅ **Authentic OpenSSH** |
| **Anti-VM / Procfs Evasion** | ❌ (Static `/proc`) | ❌ (`/.dockerenv`, cgroups) | ✅ **Undetectable** |
| **State Reset & Isolation** | ⚠️ Partial | ⚠️ Slow reset | ✅ **Instant RAM Discard** |
| **Malware Binary Execution** | ❌ (Fails on real ELFs) | ⚠️ Risk to host kernel | ✅ **Isolated Hardware VM** |

---

## 🚀 Quick Start (One-Liner Install)

Run the installer on any Linux server:

```bash
git clone https://github.com/yourusername/ghostpot.git
cd ghostpot
chmod +x install.sh
sudo ./install.sh
```

The installer will:
1. Detect hardware KVM support (falls back to QEMU TCG if running on nested-disabled VPS).
2. Ask which honeypots to activate (**SSH [22]**, **Telnet [23]**).
3. Generate a secure random port and secret URL slug for your Web Intelligence Dashboard.
4. Launch everything via Docker Compose.

---

## 🐳 Docker Compose Manual Deployment

```bash
# 1. Clone repository
git clone https://github.com/yourusername/ghostpot.git
cd ghostpot

# 2. Edit configuration
cp config.yaml config.yaml.local
nano config.yaml

# 3. Launch
docker compose up -d --build
```

---

## ⚙️ Configuration (`config.yaml`)

```yaml
services:
  ssh:
    enabled: true            # Toggle SSH honeypot
    listen_port: 22          # Attacker-facing port
    target_port: 2222
  telnet:
    enabled: true            # Toggle Telnet honeypot
    listen_port: 23          # Attacker-facing port
    target_port: 2323

web:
  host: "0.0.0.0"
  port: 48921                # Random high port for dashboard
  secret_slug: "ghost_sec_9f2a7b8e14" # Secret URL path (Anti-Crawler)

vm:
  pool_size: 2               # Pre-warmed VMs in RAM
  memory_mb: 128             # RAM per MicroVM
  vcpus: 1
  use_kvm: null              # null = auto-detect /dev/kvm
  kernel_path: "kernel/vmlinuz"
  rootfs_path: "rootfs/alpine-rootfs.raw"
  tmpfs_dir: "/dev/shm/ghostpot"

storage:
  db_path: "data/ghostpot.db"
  downloads_dir: "data/downloads"
```

---

## 🗺️ Web Dashboard Navigation

Once started, access your secret dashboard at:
```text
http://YOUR_SERVER_IP:<PORT>/<SECRET_SLUG>/
```

- **Dashboard:** Real-time attack counter, country map, threat timeline, top bruteforce credentials, and live activity feed.
- **Sessions Cloud:** List of all attacker connections categorized by campaign (*IoT Botnet, Miner, Exploit, Bruteforce*).
- **Session Detail:** Visual execution graph showing every event, command, auth attempt, and downloaded binary.

---

## 📜 License
MIT License. Created for threat intelligence research and defensive security engineering.
