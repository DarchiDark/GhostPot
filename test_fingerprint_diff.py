#!/usr/bin/env python3
import sys
import subprocess
import paramiko
import time

PROBE_SCRIPT = r"""export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
uname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null || /usr/bin/uname -s -v -n -m 2>/dev/null || busybox uname -s -v -n -m 2>/dev/null || ( [ -f /proc/version ] && head -1 /proc/version | cut -d' ' -f1 ) || ( [ -f /etc/os-release ] && grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' ) || echo "")
arch=$(uname -m 2>/dev/null || /bin/uname -m 2>/dev/null || /usr/bin/uname -m 2>/dev/null || busybox uname -m 2>/dev/null || ( [ -f /proc/cpuinfo ] && grep -q "lm" /proc/cpuinfo && echo x86_64 ) || ( [ -f /proc/cpuinfo ] && grep -q "CPU architecture: 8" /proc/cpuinfo && echo aarch64 ) || ( [ -f /proc/cpuinfo ] && grep -q "CPU architecture: 7" /proc/cpuinfo && echo armv7l ) || echo "")
uptime=$(cat /proc/uptime 2>/dev/null || busybox cat /proc/uptime 2>/dev/null)
cpus=$(nproc 2>/dev/null || /usr/bin/nproc 2>/dev/null || busybox nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null)
cpu_model=$( { lscpu 2>/dev/null | awk -F: '/Model name/ {print $2}'; grep -m1 -E "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2-; grep -m1 -E "^Hardware" /proc/cpuinfo 2>/dev/null | cut -d: -f2-; cat /proc/device-tree/model 2>/dev/null; } | sed '/^$/d; /unknown/d; s/^[[:space:]]*//; s/[[:space:]]*$//; s/ AArch64 Processor$//; s/ Processor$//; s/ CPU$//' | head -1 )
gpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia; busybox lspci 2>/dev/null | grep -i vga; busybox lspci 2>/dev/null | grep -i nvidia) 2>/dev/null )
last_output=$(last 2>/dev/null)
filter_output=$( ( export LANG=C LC_ALL=C; echo '===SHELL_BEHAVIOR==='; printf 'path_err='; ( ./xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d '\n' 2>/dev/null || busybox tr -d '\n' 2>/dev/null || cat ); printf '\n'; printf 'cmd_err='; ( xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d '\n' 2>/dev/null || busybox tr -d '\n' 2>/dev/null || cat ); printf '\n'; printf 'execute_err='; out=$(bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(/bin/bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(/usr/bin/bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(busybox sh -c 'printf "#!/bin/sh\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1 || sh -c 'printf "#!/bin/sh\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); esac; esac; esac; printf '%s' "$out" | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d '\n' 2>/dev/null || busybox tr -d '\n' 2>/dev/null || cat ); printf '\n'; echo '===DONE===' ) 2>&1 )
echo "UNAME:$uname"
echo "ARCH:$arch"
echo "UPTIME:$uptime"
echo "CPUS:$cpus"
echo "CPU_MODEL:$cpu_model"
echo "GPU:$gpu_info"
echo "LAST:$last_output"
echo "FILTER:$filter_output"
"""

def parse_output(raw: str) -> dict:
    result = {}
    lines = raw.strip().split("\n")
    current_key = None
    buffer = []
    
    for line in lines:
        matched_prefix = False
        for prefix in ["UNAME:", "ARCH:", "UPTIME:", "CPUS:", "CPU_MODEL:", "GPU:", "LAST:", "FILTER:"]:
            if line.startswith(prefix):
                if current_key:
                    result[current_key] = "\n".join(buffer).strip()
                current_key = prefix[:-1]
                buffer = [line[len(prefix):]]
                matched_prefix = True
                break
        if not matched_prefix and current_key:
            buffer.append(line)
            
    if current_key:
        result[current_key] = "\n".join(buffer).strip()
    return result

def run_on_host() -> dict:
    print("[*] Running fingerprint probe directly on HOST...")
    proc = subprocess.run(["/bin/bash", "-c", PROBE_SCRIPT], capture_output=True, text=True)
    return parse_output(proc.stdout)

def run_on_honeypot(host="127.0.0.1", port=22, user="root", password="password123") -> dict:
    print(f"[*] Connecting to HONEYPOT over SSH ({host}:{port})...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command(PROBE_SCRIPT)
        output = stdout.read().decode("utf-8", "ignore")
        client.close()
        return parse_output(output)
    except Exception as e:
        print(f"[-] SSH Error connecting to honeypot: {e}")
        return {}

def main():
    host_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    
    host_data = run_on_host()
    hp_data = run_on_honeypot(host=host_ip, port=port)
    
    if not hp_data:
        print("[-] Could not retrieve data from Honeypot. Is Ghostpot running?")
        sys.exit(1)
        
    print("\n" + "="*80)
    print(f"{'PARAMETER':<15} | {'HOST VALUE':<30} | {'HONEYPOT VALUE':<30}")
    print("="*80)
    
    all_keys = set(host_data.keys()).union(set(hp_data.keys()))
    differences = []
    
    for k in sorted(all_keys):
        val_host = host_data.get(k, "<N/A>")
        val_hp = hp_data.get(k, "<N/A>")
        
        # Format for short display
        display_host = (val_host[:27] + "...") if len(val_host) > 30 else val_host
        display_hp = (val_hp[:27] + "...") if len(val_hp) > 30 else val_hp
        
        diff_flag = "❌ DIFFERENT" if val_host != val_hp else "✓ IDENTICAL"
        if val_host != val_hp:
            differences.append((k, val_host, val_hp))
            
        print(f"{k:<15} | {display_host:<30} | {display_hp:<30} | {diff_flag}")
        
    print("="*80)
    print(f"Total parameters checked: {len(all_keys)}")
    print(f"Total differences found:  {len(differences)}")
    
    if differences:
        print("\n🔍 DETAILED DIFFERENCES:")
        for k, h, hp in differences:
            print(f"\n--- [{k}] ---")
            print(f"HOST:\n{h}")
            print(f"HONEYPOT:\n{hp}")

if __name__ == "__main__":
    main()
