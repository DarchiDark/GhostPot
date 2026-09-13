import random
import time

PROFILES = [
    {
        "os_name": "Ubuntu 22.04 LTS",
        "ssh_banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "kex_algs": [
            "curve25519-sha256", "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
            "sntrup761x25519-sha512@openssh.com", "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256"
        ],
        "mac_algs": [
            "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
            "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"
        ],
        "encryption_algs": [
            "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr",
            "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"
        ],
        "kernel": "5.15.0-100-generic",
        "gcc": "gcc-11 (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
    },
    {
        "os_name": "Debian 12",
        "ssh_banner": "OpenSSH_9.2p1 Debian-2+deb12u3",
        "kex_algs": [
            "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
            "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"
        ],
        "mac_algs": [
            "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
            "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"
        ],
        "encryption_algs": [
            "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr",
            "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"
        ],
        "kernel": "6.1.0-23-amd64",
        "gcc": "gcc-12 (Debian 12.2.0-14) 12.2.0"
    }
]

def generate_persona():
    profile = random.choice(PROFILES)
    disk_gb = random.choice([20, 40, 60, 80, 100])
    ram_mb = random.choice([1024, 2048, 4096, 8192])
    uptime_seconds = random.randint(3600, 86400 * 300) # 1 hour to 300 days
    cpu_models = [
        "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
        "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
        "AMD EPYC 7742 64-Core Processor",
        "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz"
    ]
    
    return {
        "profile": profile,
        "disk_gb": disk_gb,
        "ram_mb": ram_mb,
        "uptime": uptime_seconds,
        "cpu": random.choice(cpu_models),
        "hostname": f"{random.choice(['web', 'db', 'app', 'stage', 'prod', 'test'])}-{random.randint(1,99)}"
    }

def generate_fake_mounts(persona):
    size = persona["disk_gb"]
    return f"""/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
udev /dev devtmpfs rw,nosuid,relatime,size={persona['ram_mb']*1000}k,mode=755,inode64 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size={persona['ram_mb']*200}k,mode=755,inode64 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
"""

def generate_fake_mountinfo(persona):
    size = persona["disk_gb"]
    return f"""36 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro
37 36 0:6 / /dev rw,nosuid,relatime - devtmpfs udev rw,size={persona['ram_mb']*1000}k,mode=755
38 37 0:23 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=000
39 36 0:24 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size={persona['ram_mb']*200}k,mode=755
40 36 0:25 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
41 36 0:26 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
"""

def generate_dmesg_script(persona):
    kernel = persona["profile"]["kernel"]
    gcc = persona["profile"]["gcc"]
    cpu = persona["cpu"]
    disk_gb = persona["disk_gb"]
    blocks = disk_gb * 2097152
    
    return f"""#!/bin/bash
cat << "DMESGLOG"
[    0.000000] Linux version {kernel} ({gcc})
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-{kernel} root=/dev/sda1 ro quiet
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000dfffffff] usable
[    0.152431] smpboot: CPU0: {cpu} (family: 0x6, model: 0x4f, stepping: 0x1)
[    0.512344] pci 0000:00:01.0: [8086:2918] type 00 class 0x060100
[    0.781290] ata1: SATA max UDMA/133 abar m2048@0xfebf0000 port 0xfebf0100 irq 43
[    0.912340] scsi 0:0:0:0: Direct-Access     ATA      QEMU HARDDISK    2.5+ PQ: 0 ANSI: 5
[    1.012450] sd 0:0:0:0: [sda] {blocks} 512-byte logical blocks: ({disk_gb}.0 GB)
[    1.012455] sd 0:0:0:0: [sda] Write Protect is off
[    1.012500]  sda: sda1
[    1.013100] sd 0:0:0:0: [sda] Attached SCSI disk
[    1.456789] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.
[    2.123456] systemd[1]: Inserted module 'autofs4'
[    2.567890] systemd[1]: Mounted /boot.
[    3.120980] systemd[1]: Started OpenBSD Secure Shell server.
[    3.200100] systemd[1]: Reached target Multi-User System.
DMESGLOG
"""

def generate_systemctl_script(persona):
    hostname = persona["hostname"]
    return f"""#!/bin/bash
if [ "$1" = "list-units" ] || [ "$1" = "list-unit-files" ] || [ -z "$1" ]; then
    echo "  UNIT                          LOAD   ACTIVE SUB     DESCRIPTION"
    echo "  cron.service                  loaded active running Regular background program processing daemon"
    echo "  dbus.service                  loaded active running D-Bus System Message Bus"
    echo "  getty@tty1.service            loaded active running Getty on tty1"
    echo "  rsyslog.service               loaded active running System Logging Service"
    echo "  ssh.service                   loaded active running OpenBSD Secure Shell server"
    echo "  systemd-journald.service      loaded active running Journal Service"
    echo "  systemd-logind.service        loaded active running User Login Management"
    echo "  systemd-timesyncd.service     loaded active running Network Time Synchronization"
    echo "  systemd-udevd.service         loaded active running Rule-based Manager for Device Events and Files"
    echo ""
    echo "LOAD   = Reflects whether the unit definition was properly loaded."
    echo "ACTIVE = The high-level unit activation state, i.e. generalization of SUB."
    echo "SUB    = The low-level unit activation state, values depend on unit type."
    echo "9 loaded units listed."
    exit 0
elif [ "$1" = "status" ] || [ "$1" = "is-active" ]; then
    unit="${{2:-ssh}}"
    unit_clean="${{unit%.service}}"
    echo "● ${{unit_clean}}.service - ${{unit_clean}} service"
    echo "     Loaded: loaded (/lib/systemd/system/${{unit_clean}}.service; enabled; preset: enabled)"
    echo "     Active: active (running) since Mon 2026-08-31 00:00:00 UTC; 22h ago"
    echo "   Main PID: 412 (${{unit_clean}})"
    echo "      Tasks: 1 (limit: 4686)"
    echo "     Memory: 3.2M"
    echo "        CPU: 120ms"
    echo "     CGroup: /system.slice/${{unit_clean}}.service"
    echo "             └─412 /usr/sbin/${{unit_clean}}"
    echo ""
    echo "Aug 31 00:00:00 {hostname} systemd[1]: Started ${{unit_clean}}.service."
    exit 0
fi
exit 0
"""

def generate_service_script():
    return """#!/bin/bash
if [ "$2" = "status" ] || [ "$2" = "restart" ] || [ "$2" = "start" ] || [ "$2" = "stop" ]; then
    echo " * $1 is running"
    exit 0
fi
exit 0
"""

def generate_journalctl_script(persona):
    hostname = persona.get("hostname", "srv-01")
    return f"""#!/bin/bash
echo "-- Logs begin at Mon 2026-08-31 00:00:00 UTC, end at Tue 2026-09-01 12:00:00 UTC. --"
echo "Sep 01 04:12:01 {hostname} CRON[1204]: (root) CMD (/usr/lib/x86_64-linux-gnu/sa/sa1 1 1)"
echo "Sep 01 05:00:01 {hostname} systemd[1]: Starting Daily apt download activities..."
echo "Sep 01 05:00:15 {hostname} systemd[1]: apt-daily.service: Deactivated successfully."
echo "Sep 01 06:17:01 {hostname} CRON[2390]: (root) CMD (   test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))"
echo "Sep 01 08:30:11 {hostname} sshd[3102]: Server listening on 0.0.0.0 port 22."
exit 0
"""

def generate_apt_script():
    return """#!/bin/bash
if [ "$1" = "update" ]; then
    echo "Hit:1 http://deb.debian.org/debian bookworm InRelease"
    echo "Hit:2 http://security.debian.org/debian-security bookworm-security InRelease"
    echo "Reading package lists... Done"
    echo "Building dependency tree... Done"
    exit 0
fi
if [ "$1" = "install" ]; then
    echo "Reading package lists... Done"
    echo "Building dependency tree... Done"
    echo "E: Unable to locate package $2"
    exit 100
fi
exit 0
"""

