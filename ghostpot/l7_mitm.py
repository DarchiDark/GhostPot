import asyncio
import asyncssh
import logging
import secrets
import os
from ghostpot.config import AppConfig
from ghostpot.database import Database
from ghostpot.vm_manager import VMPoolManager
from ghostpot.personality import generate_persona, generate_dmesg_script, generate_systemctl_script, generate_fake_mounts

logger = logging.getLogger("ghostpot.proxy")

class MitmSession(asyncssh.SSHServerSession):
    def __init__(self, session_id, src_ip, db, vm_pool, config: AppConfig):
        self.session_id = session_id
        self.src_ip = src_ip
        self.db = db
        self.vm_pool = vm_pool
        self.config = config
        self.vm = None
        self.guest_conn = None
        self.guest_chan = None
        self.client_chan = None
        self.term_type = "vt100"
        self.term_size = (80, 24)
        self.term_modes = {}
        self.command = None
        self.threat_score = 0
        
        # Buffer early inputs from fast automated bots
        self.early_input_buffer = []
        self.is_guest_ready = False
        
        # Line buffer for logging clean commands instead of single keystrokes
        self.current_line = []

    def _add_threat_score(self, points: int, reason: str):
        scoring_cfg = getattr(self.config.network, "threat_scoring", None) if hasattr(self.config, "network") else None
        if not scoring_cfg or not scoring_cfg.enabled:
            return
        
        self.threat_score += points
        logger.info(f"[!] Session {self.session_id} Threat Score: {self.threat_score}/{scoring_cfg.max_score_threshold} (+{points} for {reason})")
        if self.threat_score >= scoring_cfg.max_score_threshold:
            logger.warning(f"[🚨] Session {self.session_id} exceeded Threat Score limit ({self.threat_score})! Triggering auto-kill & artifact extraction...")
            if self.client_chan and not self.client_chan.is_closed():
                self.client_chan.write(b"\r\nConnection terminated by security policy.\r\n")
                self.client_chan.close()
            if self.guest_chan and not self.guest_chan.is_closed():
                self.guest_chan.close()
            if self.vm:
                asyncio.create_task(self.vm_pool.release_vm(self.session_id))

    def _evaluate_command_threat(self, cmd: str):
        cmd_lower = cmd.lower()
        # LAN scan / reconnaissance
        if any(tool in cmd_lower for tool in ["nmap", "masscan", "zmap", "192.168.", "10.0.", "172.16."]):
            self._add_threat_score(self.config.network.threat_scoring.penalty_private_lan, "LAN scan / recon attempt")
        # Destructive or forkbomb commands
        elif any(tool in cmd_lower for tool in [":(){ :|:& };:", "mkfs", "dd if=/dev/zero", "rm -rf /", "chmod -R 777 /"]):
            self._add_threat_score(self.config.network.threat_scoring.penalty_destructive_cmd, "Destructive system command")
        # Attack tools
        elif any(tool in cmd_lower for tool in ["hydra", "medusa", "xmrig", "minerd", "stratum+tcp"]):
            self._add_threat_score(25, "Malicious tool or cryptominer launch")

    # Server Callbacks (from attacker)
    def connection_made(self, chan):
        self.client_chan = chan

    def pty_requested(self, term_type, term_size, term_modes):
        self.term_type = term_type
        self.term_size = term_size
        self.term_modes = term_modes
        return True

    def window_change_requested(self, width, height, pixwidth, pixheight):
        self.term_size = (width, height)
        if self.guest_chan and not self.guest_chan.is_closed():
            self.guest_chan.change_terminal_size(width, height, pixwidth, pixheight)
        return True

    def shell_requested(self):
        asyncio.create_task(self._initiate_guest_session(command=None))
        return True

    def exec_requested(self, command):
        self.command = command
        asyncio.create_task(self.db.record_event({
            "eventid": "cowrie.command.input",
            "input": command,
            "session": self.session_id,
            "message": f"Command exec: {command}"
        }))
        asyncio.create_task(self._initiate_guest_session(command=command))
        return True

    def data_received(self, data, datatype):
        # 1. Process line buffer for clean command history
        if isinstance(data, (bytes, bytearray)):
            text = data.decode("latin1", "ignore")
        else:
            text = str(data)

        for char in text:
            if char in ('\r', '\n'):
                full_cmd = "".join(self.current_line).strip()
                if full_cmd:
                    self._evaluate_command_threat(full_cmd)
                    asyncio.create_task(self.db.record_event({
                        "eventid": "cowrie.command.input",
                        "input": full_cmd,
                        "session": self.session_id,
                        "message": f"CMD: {full_cmd}"
                    }))
                self.current_line = []
            elif char in ('\x08', '\x7f'): # Backspace
                if self.current_line:
                    self.current_line.pop()
            elif char >= ' ' or char == '\t':
                self.current_line.append(char)

        # 2. Prevent race conditions: Buffer inputs if VM connection is still establishing
        if not self.is_guest_ready or not self.guest_chan:
            self.early_input_buffer.append((data, datatype))
        else:
            self.guest_chan.write(data, datatype=datatype)

    def eof_received(self):
        if self.guest_chan and not self.guest_chan.is_closed():
            self.guest_chan.write_eof()

    def connection_lost(self, exc):
        if self.guest_chan and not self.guest_chan.is_closed():
            self.guest_chan.close()
        if self.guest_conn and not self.guest_conn.is_closed():
            self.guest_conn.close()
        if self.vm:
            asyncio.create_task(self.vm_pool.release_vm(self.session_id))

    # Client Callbacks (from internal VM guest)
    def data_received_from_guest(self, data, datatype):
        if self.client_chan and not self.client_chan.is_closing():
            self.client_chan.write(data, datatype=datatype)

    def eof_received_from_guest(self):
        if self.client_chan and not self.client_chan.is_closing():
            self.client_chan.write_eof()

    def exit_status_received_from_guest(self, status):
        if self.client_chan and not self.client_chan.is_closing():
            self.client_chan.exit(status)

    def exit_signal_received_from_guest(self, signal, core_dumped, msg, lang):
        if self.client_chan and not self.client_chan.is_closing():
            self.client_chan.exit_signal(signal, core_dumped, msg, lang)

    def guest_connection_lost(self, exc):
        if self.client_chan and not self.client_chan.is_closing():
            self.client_chan.close()

    async def _initiate_guest_session(self, command=None):
        try:
            from ghostpot.personality import generate_service_script, generate_journalctl_script, generate_apt_script
            persona = generate_persona()
            self.vm = await self.vm_pool.acquire_vm(self.session_id)
            
            # Inject dynamic persona & fake system binaries (Anti-Heuristic Polymorphism)
            with open(f"{self.vm.merged_dir}/usr/bin/dmesg", "w") as f: f.write(generate_dmesg_script(persona))
            with open(f"{self.vm.merged_dir}/usr/bin/systemctl", "w") as f: f.write(generate_systemctl_script(persona))
            with open(f"{self.vm.merged_dir}/usr/sbin/service", "w") as f: f.write(generate_service_script())
            with open(f"{self.vm.merged_dir}/usr/bin/journalctl", "w") as f: f.write(generate_journalctl_script(persona))
            with open(f"{self.vm.merged_dir}/usr/bin/apt-get", "w") as f: f.write(generate_apt_script())
            with open(f"{self.vm.merged_dir}/usr/bin/apt", "w") as f: f.write(generate_apt_script())
            with open(f"{self.vm.merged_dir}/etc/fake_mounts", "w") as f: f.write(generate_fake_mounts(persona))
            
            for b in ["dmesg", "systemctl", "journalctl", "apt-get", "apt"]:
                os.chmod(f"{self.vm.merged_dir}/usr/bin/{b}", 0o755)
            os.chmod(f"{self.vm.merged_dir}/usr/sbin/service", 0o755)
            
            target_ip = getattr(self.vm, "guest_ip", "127.0.0.1")
            target_port = getattr(self.vm, "host_ssh_port", 22)
            
            self.guest_conn = await asyncssh.connect(
                target_ip, port=target_port, 
                username="root", password="", 
                known_hosts=None
            )
            
            # Bridge callbacks from VM guest back to attacker client
            class GuestSessionBridge(asyncssh.SSHClientSession):
                def __init__(self, parent):
                    self.parent = parent
                def data_received(self, data, datatype):
                    self.parent.data_received_from_guest(data, datatype)
                def eof_received(self):
                    self.parent.eof_received_from_guest()
                def exit_status_received(self, status):
                    self.parent.exit_status_received_from_guest(status)
                def exit_signal_received(self, signal, core_dumped, msg, lang):
                    self.parent.exit_signal_received_from_guest(signal, core_dumped, msg, lang)
                def connection_lost(self, exc):
                    self.parent.guest_connection_lost(exc)
                    if self.parent.client_chan and not self.parent.client_chan.is_closing():
                        self.parent.client_chan.close()

            if command:
                self._evaluate_command_threat(command)
                self.guest_chan, _ = await self.guest_conn.create_session(
                    lambda: GuestSessionBridge(self), command=command
                )
            else:
                self.guest_chan, _ = await self.guest_conn.create_session(
                    lambda: GuestSessionBridge(self),
                    term_type=self.term_type,
                    term_size=self.term_size,
                    term_modes=self.term_modes
                )

            # Flush any early data sent by fast botnets while we were establishing the connection
            self.is_guest_ready = True
            while self.early_input_buffer:
                early_data, datatype = self.early_input_buffer.pop(0)
                self.guest_chan.write(early_data, datatype=datatype)

        except Exception as e:
            logger.error(f"MitM Guest initialization failed: {e}")
            if self.client_chan and not self.client_chan.is_closed():
                self.client_chan.close()


class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, config: AppConfig, db: Database, vm_pool: VMPoolManager):
        self.config = config
        self.db = db
        self.vm_pool = vm_pool
        self.session_id = secrets.token_hex(6)
        self.src_ip = "0.0.0.0"
        self.authenticated = False
        self.auth_attempts = 0

    def connection_made(self, conn):
        self.src_ip = conn.get_extra_info('peername')[0]
        logger.info(f"[*] New L7 MitM SSH connection from {self.src_ip} [Session: {self.session_id}]")
        asyncio.create_task(self.db.record_event({
            "eventid": "cowrie.session.connect",
            "src_ip": self.src_ip,
            "session": self.session_id,
            "protocol": "ssh",
            "message": f"New connection: {self.src_ip} via L7 MitM"
        }))

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.auth_attempts += 1
        cfg = getattr(self.config, "auth", None)
        min_att = getattr(cfg, "min_attempts", 1) if cfg else 1
        mode = getattr(cfg, "mode", "dynamic") if cfg else "dynamic"

        # Dynamic bruteforce simulation or accept all
        if mode == "accept_all" or self.auth_attempts >= min_att:
            self.authenticated = True
            asyncio.create_task(self.db.record_event({
                "eventid": "cowrie.login.success",
                "username": username, "password": password,
                "src_ip": self.src_ip, "session": self.session_id,
                "message": f"Login success [{username}/{password}]"
            }))
            return True
        else:
            asyncio.create_task(self.db.record_event({
                "eventid": "cowrie.login.failed",
                "username": username, "password": password,
                "src_ip": self.src_ip, "session": self.session_id,
                "message": f"Login failed [{username}/{password}] (Attempt {self.auth_attempts})"
            }))
            return False

    def public_key_auth_supported(self):
        return getattr(self.config.auth, "allow_publickey", True)

    def validate_public_key(self, username, key):
        if getattr(self.config.auth, "allow_publickey", True):
            self.authenticated = True
            key_fp = key.get_fingerprint() if hasattr(key, 'get_fingerprint') else 'unknown'
            asyncio.create_task(self.db.record_event({
                "eventid": "cowrie.login.success",
                "username": username, "password": f"[PublicKey: {key_fp}]",
                "src_ip": self.src_ip, "session": self.session_id,
                "message": f"Login PublicKey [{username}] {key_fp}"
            }))
            return True
        return False

    def session_requested(self):
        # If password is required and user did not authenticate, check allow_none_auth
        if not self.authenticated and getattr(self.config.auth, "require_password", True):
            if not getattr(self.config.auth, "allow_none_auth", False):
                logger.warning(f"[-] Session {self.session_id} rejected: Unauthenticated session request (None auth blocked).")
                return None
        return MitmSession(self.session_id, self.src_ip, self.db, self.vm_pool, self.config)


class L7MitmProxyServer:
    def __init__(self, config: AppConfig, db: Database, vm_pool: VMPoolManager):
        self.config = config
        self.db = db
        self.vm_pool = vm_pool
        self.global_persona = generate_persona()

    async def start(self):
        ssh_port = self.config.services.ssh.listen_port
        logger.info(f"[+] Polymorphic Profile Selected: {self.global_persona['profile']['os_name']}")
        logger.info(f"    - SSH Banner: {self.global_persona['profile']['ssh_banner']}")
        logger.info(f"    - Kernel: {self.global_persona['profile']['kernel']}")
        logger.info(f"    - CPU: {self.global_persona['cpu']}")
        
        self.server = await asyncssh.create_server(
            lambda: HoneySSHServer(self.config, self.db, self.vm_pool),
            host='0.0.0.0', 
            port=ssh_port,
            server_host_keys=['data/ssh_host_rsa_key'],
            server_version=self.global_persona['profile']['ssh_banner']
        )
        logger.info(f"[+] L7 SSH MitM Engine listening on 0.0.0.0:{ssh_port}")

    async def stop(self):
        if hasattr(self, 'server') and self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("[-] L7 SSH MitM Engine stopped.")
