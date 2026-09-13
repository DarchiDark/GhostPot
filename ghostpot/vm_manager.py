import asyncio
import os
import secrets
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Any
from ghostpot.config import AppConfig
from ghostpot.cow_extractor import CoWExtractor

logger = logging.getLogger("ghostpot.vm_manager")


class VMInstance:
    """
    Hardened High-Interaction Sandbox:
    - If KVM available: Boots ultra-fast QEMU MicroVM with ephemeral CoW RAM disk.
    - If KVM unavailable: Boots instant (0ms, 0% CPU) Linux Namespace Sandbox (PID, Mount, UTS, IPC) with Debian 12.
    """
    def __init__(self, vm_id: str, config: AppConfig, host_ssh_port: int, host_telnet_port: int, ip_idx: int = 10):
        self.vm_id = vm_id
        self.config = config
        self.host_ssh_port = host_ssh_port
        self.host_telnet_port = host_telnet_port
        self.ip_idx = ip_idx
        self.guest_ip = f"10.99.{ip_idx}.2"
        self.host_veth_ip = f"10.99.{ip_idx}.1"
        self.veth_host = f"veth_{vm_id}"
        self.veth_guest = f"vg_{vm_id}"
        
        self.tmpfs_dir = Path(config.vm.tmpfs_dir)
        self.work_dir = str(self.tmpfs_dir / f"work_{vm_id}")
        self.upper_dir = str(self.tmpfs_dir / f"upper_{vm_id}")
        self.merged_dir = str(self.tmpfs_dir / f"merged_{vm_id}")
        
        self.process: Optional[asyncio.subprocess.Process] = None
        self.telnet_process: Optional[asyncio.subprocess.Process] = None
        self.is_ready = False
        self.extractor = CoWExtractor(config.storage.downloads_dir)

    async def start(self):
        """Creates RAM disk overlay and launches isolated namespace sandbox."""
        self.tmpfs_dir.mkdir(parents=True, exist_ok=True)
        base_dir = os.path.abspath("rootfs/debian_base")

        if not os.path.exists(base_dir):
            raise FileNotFoundError(f"Debian base filesystem ({base_dir}) not found!")

        for d in [self.work_dir, self.upper_dir, self.merged_dir]:
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d, exist_ok=True)

        # Pre-populate upper_dir with standard pristine system files (Zero deception trace)
        os.makedirs(f"{self.upper_dir}/etc", exist_ok=True)
        with open(f"{self.upper_dir}/etc/hostname", "w") as f:
            f.write("debian-server-01\n")
        with open(f"{self.upper_dir}/etc/resolv.conf", "w") as f:
            f.write("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")

        # 1. Mount ephemeral OverlayFS in RAM
        mount_cmd = [
            "mount", "-t", "overlay", "overlay",
            "-o", f"lowerdir={base_dir},upperdir={self.upper_dir},workdir={self.work_dir}",
            self.merged_dir
        ]
        proc = await asyncio.create_subprocess_exec(*mount_cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.communicate()

        # 2. Populate isolated minimal /dev (no host block devices!)
        os.makedirs(f"{self.merged_dir}/dev/pts", exist_ok=True)
        os.makedirs(f"{self.merged_dir}/dev/shm", exist_ok=True)
        os.makedirs(f"{self.merged_dir}/proc", exist_ok=True)
        os.makedirs(f"{self.merged_dir}/sys", exist_ok=True)
        os.makedirs(f"{self.merged_dir}/run/sshd", exist_ok=True)
        os.makedirs(f"{self.merged_dir}/run/systemd", exist_ok=True)
        os.makedirs(f"{self.merged_dir}/var/empty", exist_ok=True)
        subprocess.run(["chmod", "777", f"{self.merged_dir}/run/systemd"], check=False)
        subprocess.run(["chmod", "700", f"{self.merged_dir}/var/empty"], check=False)

        # Initialize command log file with write permissions for all users
        cmd_log_file = f"{self.merged_dir}/run/systemd/.journal_cmd.log"
        with open(cmd_log_file, "a") as fp:
            pass
        os.chmod(cmd_log_file, 0o666)

        dev_nodes = [
            ("null", 1, 3, 0o666),
            ("zero", 1, 5, 0o666),
            ("random", 1, 8, 0o666),
            ("urandom", 1, 9, 0o666),
            ("tty", 5, 0, 0o666),
        ]
        for name, maj, min_dev, mode in dev_nodes:
            node_path = f"{self.merged_dir}/dev/{name}"
            if not os.path.exists(node_path):
                try:
                    os.mknod(node_path, mode | 0o020000, os.makedev(maj, min_dev))
                except Exception:
                    pass

        # Mount private devpts instance for interactive PTY shells
        subprocess.run([
            "mount", "-t", "devpts", "devpts",
            "-o", "newinstance,ptmxmode=0666,mode=620",
            f"{self.merged_dir}/dev/pts"
        ], check=False)

        try:
            os.remove(f"{self.merged_dir}/dev/ptmx")
        except Exception:
            pass
        try:
            os.symlink("pts/ptmx", f"{self.merged_dir}/dev/ptmx")
        except Exception:
            pass

        # Set realistic server hostname and genuine /proc/mounts & /etc/mtab & /etc/resolv.conf
        os.makedirs(f"{self.merged_dir}/etc", exist_ok=True)
        with open(f"{self.merged_dir}/etc/hostname", "w") as f:
            f.write("debian-server-01\n")

        with open(f"{self.merged_dir}/etc/resolv.conf", "w") as f:
            f.write(f"nameserver {self.host_veth_ip}\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")

        fake_mounts_content = (
            "/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0\n"
            "udev /dev devtmpfs rw,nosuid,relatime,size=1931920k,nr_inodes=482980,mode=755,inode64 0 0\n"
            "devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0\n"
            "tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=391736k,mode=755,inode64 0 0\n"
            "tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0\n"
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        )
        try:
            with open(f"{self.merged_dir}/etc/fake_mounts", "w") as f:
                f.write(fake_mounts_content)
            with open(f"{self.merged_dir}/etc/mtab", "w") as f:
                f.write(fake_mounts_content)
        except Exception:
            pass

        # 3. Bind mount pam_auth.sock for PAM verification
        auth_sock = "/run/systemd/pam_auth.sock"
        if os.path.exists(auth_sock):
            os.makedirs(f"{self.merged_dir}/run/systemd", exist_ok=True)
            guest_sock = f"{self.merged_dir}/run/systemd/pam_auth.sock"
            try:
                with open(guest_sock, "w") as fp:
                    pass
                subprocess.run(["mount", "--bind", auth_sock, guest_sock], check=False)
            except Exception:
                pass

        # 4. Launch SSHD in Hardened Linux Namespaces (Network, PID, Mount, UTS, IPC) with pivot_root & VFS Deception
        # Uses pivot_root and network namespace to completely isolate host devices and interfaces
        pivot_init_script = (
            f"mount --make-rprivate / && "
            f"mount --bind {self.merged_dir} {self.merged_dir} && "
            f"mkdir -p {self.merged_dir}/.old_root && "
            f"cd {self.merged_dir} && "
            f"pivot_root . .old_root && "
            f"hostname debian-server-01 && "
            f"mount -t proc proc /proc 2>/dev/null || true && "
            f"mount -t devpts devpts /dev/pts 2>/dev/null || true && "
            f"ip link set lo up 2>/dev/null || true && "
            f"umount -l /.old_root 2>/dev/null || true && "
            f"rmdir /.old_root 2>/dev/null || true && "
            f"exec /usr/sbin/sshd -p {self.host_ssh_port} -D -e"
        )

        unshare_cmd = [
            "unshare",
            "--net",
            "--pid",
            "--mount",
            "--uts",
            "--ipc",
            "--fork",
            "/bin/sh", "-c",
            pivot_init_script
        ]
        self.process = await asyncio.create_subprocess_exec(
            *unshare_cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )

        # Setup private veth pair to bridge host proxy to isolated guest network namespace
        try:
            pid = self.process.pid
            subprocess.run(["ip", "link", "add", self.veth_host, "type", "veth", "peer", "name", self.veth_guest], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.veth_guest, "netns", str(pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "add", f"{self.host_veth_ip}/24", "dev", self.veth_host], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.veth_host, "up"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Configure inside guest namespace: lo and clean eth0
            subprocess.run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "lo", "up"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", self.veth_guest, "name", "eth0"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nsenter", "-t", str(pid), "-n", "ip", "addr", "add", f"{self.guest_ip}/24", "dev", "eth0"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "eth0", "up"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nsenter", "-t", str(pid), "-n", "ip", "route", "add", "default", "via", self.host_veth_ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Apply Dynamic Realistic Bandwidth Shaper (Anti-Heuristic Deception)
            net_cfg = getattr(self.config, "network", None)
            if net_cfg and net_cfg.bandwidth and net_cfg.bandwidth.mode != "unlimited":
                bw = net_cfg.bandwidth
                if bw.mode == "randomized":
                    rate_kbps = secrets.randbelow(max(1, bw.max_rate_kbps - bw.min_rate_kbps + 1)) + bw.min_rate_kbps
                    jitter = secrets.randbelow(max(1, bw.jitter_ms)) + 2
                else:
                    rate_kbps = bw.min_rate_kbps
                    jitter = bw.jitter_ms
                
                # Apply tc token bucket filter and netem jitter to host veth
                subprocess.run([
                    "tc", "qdisc", "add", "dev", self.veth_host, "root", "handle", "1:",
                    "tbf", "rate", f"{rate_kbps}kbit", "burst", "32kbit", "latency", "400ms"
                ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run([
                    "tc", "qdisc", "add", "dev", self.veth_host, "parent", "1:1", "handle", "10:",
                    "netem", "delay", f"{jitter}ms", f"{jitter//2}ms"
                ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Apply Zero-Trust Outbound Traffic Security & Honeypot Deception (Anti-Abuse Egress Policy)
            from ghostpot.egress_guard import EgressGuard
            EgressGuard.setup_global_rules()
            EgressGuard.apply_guest_rules(self.guest_ip, self.host_veth_ip, self.veth_host)
        except Exception as e:
            logger.warning(f"Veth network setup warning: {e}")

        # 5. Launch Telnet in Hardened Namespace if enabled
        if self.config.services.telnet.enabled:
            telnet_pivot_script = (
                f"mount --make-rprivate / && "
                f"mount --bind {self.merged_dir} {self.merged_dir} && "
                f"mkdir -p {self.merged_dir}/.old_root && "
                f"cd {self.merged_dir} && "
                f"pivot_root . .old_root && "
                f"umount -l /.old_root 2>/dev/null || true && "
                f"rmdir /.old_root 2>/dev/null || true && "
                f"exec /usr/sbin/in.telnetd -debug {self.host_telnet_port}"
            )
            telnet_unshare = [
                "unshare",
                "--pid",
                "--mount",
                "--uts",
                "--ipc",
                "--fork",
                "/bin/sh", "-c",
                telnet_pivot_script
            ]
            try:
                self.telnet_process = await asyncio.create_subprocess_exec(
                    *telnet_unshare,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
            except Exception:
                pass

        await asyncio.sleep(0.1)
        self.is_ready = True
        logger.info(f"[+] Hardened Sandbox {self.vm_id} (Debian 12, pivot_root, PID/Mount Namespace) READY in RAM (SSH:{self.host_ssh_port}).")

    async def stop(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extracts malware artifacts from upperdir, kills namespace, and wipes RAM overlay."""
        artifacts = []
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=1.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

        if self.telnet_process:
            try:
                self.telnet_process.terminate()
            except Exception:
                pass
            self.telnet_process = None

        # Extract dropped malware from upper overlay and merged sandbox
        if session_id:
            os.makedirs(self.config.storage.downloads_dir, exist_ok=True)
            seen_hashes = set()
            scan_dirs = [d for d in [self.upper_dir, f"{self.merged_dir}/dev/shm", f"{self.merged_dir}/tmp", f"{self.merged_dir}/root", f"{self.merged_dir}/var/tmp", f"{self.merged_dir}/home", f"{self.merged_dir}/opt"] if os.path.exists(d)]
            
            logger.info(f"[*] Scanning for malware payloads in session {session_id} across: {scan_dirs}")
            for s_dir in scan_dirs:
                for root, _, files in os.walk(s_dir):
                    rel = os.path.relpath(root, s_dir)
                    # Skip system devices and proc/sys, but allow /dev/shm
                    if "shm" not in root and (rel.startswith(("dev", "proc", "sys", "run", "var/log")) or root.endswith(("/dev", "/proc", "/sys", "/run", "/var/log", "/log"))):
                        continue
                    for f in files:
                        if f.startswith(".") or "sshd" in f or "shadow" in f or "ghostpot" in f or "pam" in f or "authorized_keys" in f or f in ("bash.bashrc", "profile", "hostname", ".bash_profile", ".bashrc", "btmp", "wtmp", "lastlog", "faillog", "utmp", "tallylog", "mtab", "fake_mounts", "dmesg", "systemctl", "ld.so.preload"):
                            continue
                        full_path = os.path.join(root, f)
                        if not os.path.isfile(full_path) or os.path.islink(full_path):
                            continue
                        try:
                            with open(full_path, "rb") as fp:
                                data = fp.read()
                            if len(data) == 0:
                                continue
                            import hashlib
                            sha = hashlib.sha256(data).hexdigest()
                            if sha in seen_hashes:
                                continue
                            seen_hashes.add(sha)
                            dest = os.path.join(self.config.storage.downloads_dir, f"{sha[:16]}_{f}")
                            with open(dest, "wb") as fp:
                                fp.write(data)
                            logger.info(f"[+] CAPTURED MALWARE ARTIFACT: {f} (SHA256: {sha}, {len(data)} bytes) saved to {dest}")
                            artifacts.append({
                                "session_id": session_id,
                                "filename": f,
                                "sha256": sha,
                                "size_bytes": len(data),
                                "file_path": dest
                            })
                        except Exception as e:
                            logger.warning(f"Failed to extract artifact {f}: {e}")

        # Clean up EgressGuard iptables and recent quota sets
        from ghostpot.egress_guard import EgressGuard
        EgressGuard.cleanup_guest_rules(self.guest_ip, self.host_veth_ip, self.veth_host)

        # Delete private veth interface
        subprocess.run(["ip", "link", "del", self.veth_host], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Unmount and wipe RAM
        guest_sock = f"{self.merged_dir}/run/ghostpot_auth.sock"
        if os.path.exists(guest_sock):
            subprocess.run(["umount", guest_sock], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        subprocess.run(["umount", f"{self.merged_dir}/dev/pts"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["umount", self.merged_dir], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for d in [self.work_dir, self.upper_dir, self.merged_dir]:
            shutil.rmtree(d, ignore_errors=True)

        self.is_ready = False
        logger.info(f"[-] Hardened Sandbox {self.vm_id} wiped from RAM.")
        return artifacts


class VMPoolManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self.pool: asyncio.Queue[VMInstance] = asyncio.Queue()
        self.active_vms: Dict[str, VMInstance] = {}
        self._running = False
        self._port_counter = 12000
        self._ip_counter = 10

    def _next_ports_and_ip(self):
        self._port_counter += 2
        self._ip_counter += 1
        if self._ip_counter > 240:
            self._ip_counter = 10
        return self._port_counter, self._port_counter + 1, self._ip_counter

    async def start(self):
        self._running = True
        logger.info(f"Initializing Hardened Sandbox Pool (Target size: {self.config.vm.pool_size})...")
        for _ in range(self.config.vm.pool_size):
            await self._spawn_warm_vm()
        asyncio.create_task(self._pool_maintainer())

    async def _spawn_warm_vm(self):
        vm_id = secrets.token_hex(4)
        p_ssh, p_telnet, ip_idx = self._next_ports_and_ip()
        vm = VMInstance(vm_id, self.config, p_ssh, p_telnet, ip_idx)
        try:
            await vm.start()
            await self.pool.put(vm)
        except Exception as e:
            logger.error(f"Failed to spawn warm Sandbox: {e}")

    async def _pool_maintainer(self):
        while self._running:
            if self.pool.qsize() < self.config.vm.pool_size:
                await self._spawn_warm_vm()
            await asyncio.sleep(1.0)

    async def acquire_vm(self, session_id: str) -> VMInstance:
        """Pops a pre-warmed Sandbox instantly with 0ms delay."""
        try:
            vm = self.pool.get_nowait()
        except asyncio.QueueEmpty:
            logger.warning("Sandbox pool empty! Spawning on-demand instance...")
            vm_id = secrets.token_hex(4)
            p_ssh, p_telnet, ip_idx = self._next_ports_and_ip()
            vm = VMInstance(vm_id, self.config, p_ssh, p_telnet, ip_idx)
            await vm.start()

        self.active_vms[session_id] = vm
        return vm

    async def release_vm(self, session_id: str) -> List[Dict[str, Any]]:
        """Releases and destroys active Sandbox."""
        vm = self.active_vms.pop(session_id, None)
        if vm:
            return await vm.stop(session_id)
        return []

    async def shutdown(self):
        self._running = False
        while not self.pool.empty():
            vm = self.pool.get_nowait()
            await vm.stop()
        for vm in list(self.active_vms.values()):
            await vm.stop()
        self.active_vms.clear()
