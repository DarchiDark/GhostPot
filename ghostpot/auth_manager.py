import asyncio
import json
import logging
import os
import random
import time
from typing import Dict, Optional, Tuple
from ghostpot.config import AppConfig
from ghostpot.database import Database

logger = logging.getLogger("ghostpot.auth")


class IPAuthState:
    def __init__(self, target_attempt: int, attempt_count: int = 0, locked_username: Optional[str] = None, locked_password: Optional[str] = None, first_seen: Optional[float] = None, last_seen: Optional[float] = None):
        self.target_attempt = target_attempt
        self.attempt_count = attempt_count
        self.locked_password = locked_password
        self.locked_username = locked_username
        self.first_seen = first_seen or time.time()
        self.last_seen = last_seen or time.time()


class AuthManager:
    """
    Intelligent Adaptive Honeypot Credential & IP Binding Engine.
    - Persistent state backed by SQLite (survives container restarts).
    - Has NO hardcoded password list.
    - Accepts ANY string including empty password.
    - Rejects attempts 1..(N-1) with Permission Denied.
    - Accepts whatever the user/bot entered on attempt N (randomly 1..3).
    - Locks that specific password to this IP for the duration of TTL.
    """
    def __init__(self, config: AppConfig, db: Database, socket_path: str = "/run/systemd/pam_auth.sock"):
        self.config = config
        self.db = db
        self.socket_path = socket_path
        self.cache: Dict[str, IPAuthState] = {}
        self.port_to_ip: Dict[int, str] = {}
        self.ip_to_session: Dict[str, str] = {}
        self.server: Optional[asyncio.AbstractServer] = None
        self.ttl_seconds = config.auth.cache_ttl_hours * 3600

    def register_client(self, port: int, client_ip: str, session_id: Optional[str] = None):
        self.port_to_ip[port] = client_ip
        if session_id:
            self.ip_to_session[client_ip] = session_id

    def unregister_client(self, port: int):
        ip = self.port_to_ip.pop(port, None)
        if ip:
            self.ip_to_session.pop(ip, None)

    async def _get_or_create_state(self, ip: str) -> IPAuthState:
        now = time.time()
        if ip in self.cache:
            state = self.cache[ip]
            if now - state.last_seen > self.ttl_seconds:
                logger.info(f"Auth cache TTL expired for {ip}, resetting.")
                del self.cache[ip]
                await self._delete_db_state(ip)
            else:
                state.last_seen = now
                await self._save_db_state(ip, state)
                return state

        # Check DB for persistent state across restarts
        db_state = await self._load_db_state(ip)
        if db_state:
            if now - db_state.last_seen <= self.ttl_seconds:
                db_state.last_seen = now
                self.cache[ip] = db_state
                await self._save_db_state(ip, db_state)
                return db_state

        min_att = max(1, self.config.auth.min_attempts)
        max_att = max(min_att, self.config.auth.max_attempts)
        target = random.randint(min_att, max_att)
        state = IPAuthState(target_attempt=target)
        self.cache[ip] = state
        await self._save_db_state(ip, state)
        logger.info(f"[*] New IP {ip} registered in AuthManager (Target success attempt: {target})")
        return state

    async def _load_db_state(self, ip: str) -> Optional[IPAuthState]:
        try:
            async with self.db._db.execute("SELECT target_attempt, attempt_count, locked_username, locked_password, first_seen, last_seen FROM ip_auth_cache WHERE ip = ?", (ip,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return IPAuthState(
                        target_attempt=row[0],
                        attempt_count=row[1],
                        locked_username=row[2],
                        locked_password=row[3],
                        first_seen=float(row[4]),
                        last_seen=float(row[5])
                    )
        except Exception as e:
            logger.warning(f"Error loading auth state from DB: {e}")
        return None

    async def _save_db_state(self, ip: str, state: IPAuthState):
        try:
            await self.db._db.execute("""
                INSERT INTO ip_auth_cache (ip, target_attempt, attempt_count, locked_username, locked_password, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    attempt_count = excluded.attempt_count,
                    locked_username = excluded.locked_username,
                    locked_password = excluded.locked_password,
                    last_seen = excluded.last_seen
            """, (ip, state.target_attempt, state.attempt_count, state.locked_username, state.locked_password, str(state.first_seen), str(state.last_seen)))
            await self.db._db.commit()
        except Exception as e:
            logger.warning(f"Error saving auth state to DB: {e}")

    async def _delete_db_state(self, ip: str):
        try:
            await self.db._db.execute("DELETE FROM ip_auth_cache WHERE ip = ?", (ip,))
            await self.db._db.commit()
        except Exception:
            pass

    async def verify_login(self, ip: str, username: str, password: str) -> Tuple[bool, str]:
        mode = self.config.auth.mode.lower()

        if mode == "accept_all":
            allowed = True
            reason = "accept_all mode"
        else:
            state = await self._get_or_create_state(ip)

            if state.locked_password is not None:
                # IP already has an established locked password
                if password == state.locked_password:
                    allowed = True
                    reason = f"matched locked password for {ip}"
                else:
                    allowed = False
                    disp_locked = repr(state.locked_password) if state.locked_password else "'' (empty password)"
                    reason = f"mismatched password (locked was {disp_locked})"
            else:
                # In discovery phase (counts any attempt, including empty password!)
                state.attempt_count += 1
                if state.attempt_count >= state.target_attempt:
                    state.locked_password = password
                    state.locked_username = username
                    allowed = True
                    disp_pass = repr(password) if password else "'' (empty password)"
                    reason = f"target attempt {state.attempt_count}/{state.target_attempt} reached, locked entered password {disp_pass}"
                else:
                    allowed = False
                    reason = f"simulating rejection ({state.attempt_count}/{state.target_attempt})"

            await self._save_db_state(ip, state)

        # Record credential and event in database
        try:
            active_sid = self.ip_to_session.get(ip) or f"auth_{ip.replace('.', '_')}"
            event_type = "cowrie.login.success" if allowed else "cowrie.login.failed"
            await self.db.record_event({
                "eventid": event_type,
                "session": active_sid,
                "src_ip": ip,
                "protocol": "ssh",
                "username": username,
                "password": password,
                "message": f"Login attempt: {username}:{password} -> {'ALLOWED' if allowed else 'DENIED'} ({reason})"
            })
        except Exception as e:
            logger.error(f"Failed to record auth in DB: {e}")

        logger.info(f"Auth decision for {ip} [{username}:{password}] -> {'ALLOWED' if allowed else 'DENIED'} ({reason})")
        return allowed, reason

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # Max 512 bytes per auth check to prevent buffer exhaustion
            raw_data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            if not raw_data:
                return

            text_data = raw_data.decode("utf-8", errors="ignore").strip()
            try:
                req = json.loads(text_data, strict=False)
            except Exception:
                import re
                req = {}
                ip_m = re.search(r'"ip":\s*"([^"]*)"', text_data)
                user_m = re.search(r'"user":\s*"([^"]*)"', text_data)
                pass_m = re.search(r'"password":\s*"(.*)"\s*\}?$', text_data)
                req["ip"] = ip_m.group(1) if ip_m else "127.0.0.1"
                req["user"] = user_m.group(1) if user_m else "root"
                req["password"] = pass_m.group(1) if pass_m else ""

            ip = str(req.get("ip", "127.0.0.1"))[:64]
            port = req.get("port")
            user = str(req.get("user", "root"))[:64]
            password = str(req.get("password", ""))[:128]

            if port and port in self.port_to_ip:
                ip = self.port_to_ip[port]

            allowed, reason = await self.verify_login(ip, user, password)

            resp = json.dumps({"allow": allowed, "reason": reason}).encode("utf-8")
            writer.write(resp)
            await writer.drain()
        except Exception as e:
            logger.error(f"Error handling auth socket request: {e}")
            try:
                writer.write(json.dumps({"allow": False, "reason": "auth_error"}).encode("utf-8"))
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Starts the Unix Domain Socket server for PAM / external integration."""
        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except Exception:
                pass

        os.makedirs(os.path.dirname(self.socket_path) or "/run", exist_ok=True)
        self.server = await asyncio.start_unix_server(self._handle_client, path=self.socket_path)
        os.chmod(self.socket_path, 0o666)
        logger.info(f"[+] AuthManager Unix Socket listening at {self.socket_path}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except Exception:
                pass
        logger.info("[-] AuthManager stopped.")
