import asyncio
import os
import time
import secrets
import logging
from typing import Optional
from ghostpot.config import AppConfig
from ghostpot.database import Database
from ghostpot.vm_manager import VMPoolManager

logger = logging.getLogger("ghostpot.proxy")


class L4ProxyServer:
    def __init__(self, config: AppConfig, db: Database, vm_pool: VMPoolManager, auth_mgr=None):
        self.config = config
        self.db = db
        self.vm_pool = vm_pool
        self.auth_mgr = auth_mgr
        self.servers = []
        self.active_sessions = set()
        self.ip_concurrency = {}  # ip -> int

        # DoS and Resource Protection Limits
        self.MAX_GLOBAL_SESSIONS = 50
        self.MAX_PER_IP_SESSIONS = 5
        self.IDLE_TIMEOUT = 120.0       # 2 minutes of silence
        self.MAX_SESSION_DURATION = 900.0 # 15 minutes max per session

    async def start(self):
        # SSH is now handled by L7MitmProxyServer
        # if self.config.services.ssh.enabled:
        #     ssh_port = self.config.services.ssh.listen_port ...

        # 2. Start Telnet Proxy if enabled
        if self.config.services.telnet.enabled:
            telnet_port = self.config.services.telnet.listen_port
            server_telnet = await asyncio.start_server(
                lambda r, w: self._handle_client(r, w, protocol="telnet"),
                host="0.0.0.0",
                port=telnet_port
            )
            self.servers.append(server_telnet)
            logger.info(f"[+] Telnet Honeypot listening on 0.0.0.0:{telnet_port}")

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, protocol: str):
        session_id = secrets.token_hex(6)
        start_time = time.time()
        
        peer_addr = client_writer.get_extra_info("peername")
        src_ip = peer_addr[0] if peer_addr else "unknown"
        src_port = peer_addr[1] if peer_addr else 0
        dst_port = self.config.services.ssh.listen_port if protocol == "ssh" else self.config.services.telnet.listen_port

        # --- DoS & Concurrency Checks ---
        if len(self.active_sessions) >= self.MAX_GLOBAL_SESSIONS:
            logger.warning(f"[!] Dropping connection from {src_ip}: Global session limit reached ({self.MAX_GLOBAL_SESSIONS})")
            client_writer.close()
            return

        current_ip_count = self.ip_concurrency.get(src_ip, 0)
        if current_ip_count >= self.MAX_PER_IP_SESSIONS:
            logger.warning(f"[!] Dropping connection from {src_ip}: Per-IP limit reached ({self.MAX_PER_IP_SESSIONS})")
            client_writer.close()
            return

        self.active_sessions.add(session_id)
        self.ip_concurrency[src_ip] = current_ip_count + 1

        logger.info(f"[*] New {protocol.upper()} connection from {src_ip}:{src_port} [Session: {session_id}] (Active: {len(self.active_sessions)})")

        # Record connect event
        await self.db.record_event({
            "eventid": "cowrie.session.connect",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "session": session_id,
            "protocol": protocol,
            "message": f"New connection: {src_ip}:{src_port} ({protocol}:{dst_port})"
        })

        # Acquire a MicroVM from warm pool
        try:
            vm = await self.vm_pool.acquire_vm(session_id)
            target_port = vm.host_ssh_port if protocol == "ssh" else vm.host_telnet_port
            
            # Write real client IP for PAM authentication module
            try:
                os.makedirs(f"{vm.merged_dir}/run/systemd", exist_ok=True)
                with open(f"{vm.merged_dir}/run/systemd/net_client_ip", "w") as fp:
                    fp.write(src_ip)
            except Exception:
                pass

            if self.auth_mgr:
                self.auth_mgr.register_client(target_port, src_ip, session_id)
        except Exception as e:
            logger.error(f"Failed to acquire MicroVM for session {session_id}: {e}")
            self.active_sessions.discard(session_id)
            self.ip_concurrency[src_ip] = max(0, self.ip_concurrency.get(src_ip, 1) - 1)
            client_writer.close()
            return

        # Connect to VM (via isolated private network namespace)
        try:
            target_ip = getattr(vm, "guest_ip", "127.0.0.1")
            vm_reader, vm_writer = await asyncio.open_connection(target_ip, target_port)
        except Exception as e:
            logger.error(f"Failed to bridge to MicroVM at {getattr(vm, 'guest_ip', '127.0.0.1')}:{target_port}: {e}")
            self.active_sessions.discard(session_id)
            self.ip_concurrency[src_ip] = max(0, self.ip_concurrency.get(src_ip, 1) - 1)
            client_writer.close()
            await self.vm_pool.release_vm(session_id)
            return

        last_activity = time.time()

        # Bidirectional Pipe with Inactivity Timeout & Max Duration
        async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client_to_vm: bool):
            nonlocal last_activity
            first_packet = True
            try:
                while True:
                    # Check max duration
                    if time.time() - start_time > self.MAX_SESSION_DURATION:
                        logger.info(f"[*] Session {session_id} exceeded max duration ({self.MAX_SESSION_DURATION}s). Closing.")
                        break

                    try:
                        data = await asyncio.wait_for(reader.read(4096), timeout=self.IDLE_TIMEOUT)
                    except asyncio.TimeoutError:
                        logger.info(f"[*] Session {session_id} idle timeout ({self.IDLE_TIMEOUT}s). Closing.")
                        break

                    if not data:
                        break

                    last_activity = time.time()
                    
                    # Sniff initial SSH client version if available
                    if is_client_to_vm and first_packet and protocol == "ssh":
                        first_packet = False
                        if data.startswith(b"SSH-"):
                            banner = data.split(b"\r\n")[0].decode("latin1", errors="ignore")
                            await self.db.record_event({
                                "eventid": "cowrie.client.version",
                                "version": banner,
                                "message": f"Remote SSH version: {banner}",
                                "src_ip": src_ip,
                                "session": session_id,
                                "protocol": protocol
                            })

                    # Telnet and cleartext stream sanitization
                    if not is_client_to_vm and protocol == "telnet":
                        data = data.replace(b"/dev/shm/ghostpot", b"/var/lib/system")
                        data = data.replace(b"lowerdir=/app/rootfs", b"/dev/sda1")
                        data = data.replace(b".journal_cmd.log", b".syslog.dat")

                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        # Real-time Command Telemetry Stream
        def is_valid_user_command(cmd_str: str) -> bool:
            if not cmd_str or len(cmd_str) < 1:
                return False
            if "PROMPT_COMMAND" in cmd_str or "_gp_" in cmd_str:
                return False
            if cmd_str.startswith(("[ ", "for ", "unset ", ". ", "[[ ", "then ", "else ", "fi", "esac", "case ", "done", "return", "set -o", "shopt ", "export HIST", "export BASH_ENV")):
                return False
            if cmd_str in ["history -a", "shopt -s histappend", "return", "true", ":", "mesg n 2> /dev/null || true"]:
                return False
            return True

        cmd_stop_event = asyncio.Event()
        async def tail_commands():
            cmd_log_paths = [
                os.path.join(vm.upper_dir, "run", "systemd", ".journal_cmd.log"),
                os.path.join(vm.merged_dir, "run", "systemd", ".journal_cmd.log"),
            ]
            seen = set()
            offsets = {p: 0 for p in cmd_log_paths}

            while not cmd_stop_event.is_set():
                try:
                    for log_p in cmd_log_paths:
                        if os.path.exists(log_p):
                            with open(log_p, "r", encoding="utf-8", errors="ignore") as f:
                                f.seek(offsets[log_p])
                                new_lines = f.readlines()
                                offsets[log_p] = f.tell()

                            for line in new_lines:
                                cmd_str = line.strip()
                                if not is_valid_user_command(cmd_str) or cmd_str in seen:
                                    continue
                                seen.add(cmd_str)
                                logger.info(f"[*] [Session: {session_id}] Command executed: {cmd_str}")
                                await self.db.record_event({
                                    "eventid": "cowrie.command.input",
                                    "session": session_id,
                                    "src_ip": src_ip,
                                    "input": cmd_str,
                                    "message": f"CMD: {cmd_str}"
                                })
                except Exception as e:
                    logger.debug(f"Telemetry stream error: {e}")
                await asyncio.sleep(0.15)

        cmd_task = asyncio.create_task(tail_commands())

        try:
            await asyncio.gather(
                forward(client_reader, vm_writer, is_client_to_vm=True),
                forward(vm_reader, client_writer, is_client_to_vm=False)
            )
        finally:
            cmd_stop_event.set()
            try:
                await asyncio.wait_for(cmd_task, timeout=1.0)
            except Exception:
                pass

            # Final check of command logs and history
            try:
                check_paths = [
                    os.path.join(vm.upper_dir, "run", "systemd", ".journal_cmd.log"),
                    os.path.join(vm.merged_dir, "run", "systemd", ".journal_cmd.log"),
                    os.path.join(vm.upper_dir, "root", ".bash_history"),
                    os.path.join(vm.merged_dir, "root", ".bash_history"),
                ]
                for path in check_paths:
                    exists = os.path.exists(path)
                    logger.info(f"[*] Checking command log: {path} (exists={exists})")
                    if exists:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                cmd_str = line.strip()
                                logger.info(f"[*] Found raw cmd in {path}: {cmd_str} (valid={is_valid_user_command(cmd_str)})")
                                if is_valid_user_command(cmd_str):
                                    await self.db.record_event({
                                        "eventid": "cowrie.command.input",
                                        "session": session_id,
                                        "src_ip": src_ip,
                                        "input": cmd_str,
                                        "message": f"CMD: {cmd_str}"
                                    })
            except Exception as e:
                logger.error(f"Error in final command check: {e}")

            if self.auth_mgr:
                self.auth_mgr.unregister_client(target_port)
            duration = round(time.time() - start_time, 2)
            logger.info(f"[*] Session {session_id} closed after {duration}s")
            
            # Record session closed
            await self.db.record_event({
                "eventid": "cowrie.session.closed",
                "duration": duration,
                "src_ip": src_ip,
                "session": session_id,
                "protocol": protocol,
                "message": f"Connection lost after {duration} seconds"
            })

            # Release VM and extract any dropped malware
            artifacts = await self.vm_pool.release_vm(session_id)
            for art in artifacts:
                sha = art.get("sha256") or art.get("shasum", "")
                fname = art.get("filename", "unknown")
                fsize = art.get("size_bytes") or art.get("size", 0)
                fpath = art.get("file_path") or art.get("saved_path", "")
                await self.db.record_event({
                    "eventid": "cowrie.session.file_download",
                    "src_ip": src_ip,
                    "session": session_id,
                    "protocol": protocol,
                    "shasum": sha,
                    "sha256": sha,
                    "filename": fname,
                    "size": fsize,
                    "url": "SSH Drop",
                    "saved_path": fpath,
                    "message": f"Captured payload: {fname} (SHA256: {sha})"
                })

            # Cleanup session trackers
            self.active_sessions.discard(session_id)
            if src_ip in self.ip_concurrency:
                self.ip_concurrency[src_ip] = max(0, self.ip_concurrency[src_ip] - 1)
                if self.ip_concurrency[src_ip] == 0:
                    del self.ip_concurrency[src_ip]

    async def stop(self):
        for s in self.servers:
            s.close()
            await s.wait_closed()
        self.servers.clear()
