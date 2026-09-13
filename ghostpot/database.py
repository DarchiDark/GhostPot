import aiosqlite
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from ghostpot.geoip import lookup_ip

logger = logging.getLogger("ghostpot.database")


class Database:
    def __init__(self, db_path: str = "data/ghostpot.db"):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        # Enable WAL mode for high performance concurrent reads/writes
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA synchronous=NORMAL;")
        await self._create_tables()
        logger.info(f"Database connected at {self.db_path} (WAL enabled)")

    async def close(self):
        if self._db:
            await self._db.close()
            self._db = None

    async def _create_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                country TEXT DEFAULT 'Unknown',
                country_code TEXT DEFAULT 'UN',
                lat REAL DEFAULT 0.0,
                lng REAL DEFAULT 0.0,
                threat_level TEXT DEFAULT 'low',
                duration REAL DEFAULT 0.0,
                commands_count INTEGER DEFAULT 0,
                downloads_count INTEGER DEFAULT 0,
                events_count INTEGER DEFAULT 0,
                campaign TEXT DEFAULT 'Port Scanner',
                start_time TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
            CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                eventid TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data_json TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

            CREATE TABLE IF NOT EXISTS credentials (
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                count INTEGER DEFAULT 1,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (username, password)
            );

            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                shasum TEXT NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                url TEXT DEFAULT '',
                saved_path TEXT DEFAULT '',
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_downloads_shasum ON downloads(shasum);
        """)
        await self._db.commit()

    async def record_event(self, event: Dict[str, Any]):
        """Records an event in standard cowrie/ghostpot format and updates session/stats."""
        session_id = event.get("session")
        if not session_id:
            return

        now_iso = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        eventid = event.get("eventid", "unknown")
        src_ip = event.get("src_ip", "unknown")
        dst_port = event.get("dst_port", 22)
        protocol = event.get("protocol", "ssh")

        # Ensure session exists
        async with self._db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)) as cursor:
            session_row = await cursor.fetchone()

        if not session_row:
            geo = lookup_ip(src_ip)
            await self._db.execute("""
                INSERT INTO sessions (id, ip, port, protocol, country, country_code, lat, lng, start_time, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, src_ip, dst_port, protocol,
                geo.get("country", "Unknown"), geo.get("countryCode", "UN"),
                geo.get("lat", 0.0), geo.get("lng", 0.0),
                now_iso, now_iso
            ))
        else:
            await self._db.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (now_iso, session_id))

        # Insert event record
        await self._db.execute("""
            INSERT INTO events (session_id, eventid, timestamp, data_json)
            VALUES (?, ?, ?, ?)
        """, (session_id, eventid, now_iso, json.dumps(event)))

        # Update counters and handle specific events
        if eventid == "cowrie.session.closed":
            duration = float(event.get("duration", 0.0))
            await self._db.execute("""
                UPDATE sessions SET duration = duration + ?, events_count = events_count + 1 WHERE id = ?
            """, (duration, session_id))

        elif eventid == "cowrie.command.input":
            cmd = event.get("input", "")
            await self._db.execute("""
                UPDATE sessions SET 
                    commands_count = commands_count + 1,
                    events_count = events_count + 1,
                    threat_level = CASE WHEN threat_level = 'high' THEN 'high' ELSE 'medium' END
                WHERE id = ?
            """, (session_id,))

        elif eventid == "cowrie.session.file_download":
            shasum = event.get("shasum", "")
            url = event.get("url", "")
            size = int(event.get("size", 0))
            filename = event.get("filename", "")
            saved_path = event.get("saved_path", "")
            await self._db.execute("""
                INSERT INTO downloads (session_id, shasum, filename, size, url, saved_path, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, shasum, filename, size, url, saved_path, now_iso))

            await self._db.execute("""
                UPDATE sessions SET 
                    downloads_count = downloads_count + 1,
                    events_count = events_count + 1,
                    threat_level = 'high'
                WHERE id = ?
            """, (session_id,))

        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            username = event.get("username", "")
            password = event.get("password") or event.get("key") or ""
            if username:
                await self._db.execute("""
                    INSERT INTO credentials (username, password, count, last_seen)
                    VALUES (?, ?, 1, ?)
                    ON CONFLICT(username, password) DO UPDATE SET
                        count = count + 1,
                        last_seen = excluded.last_seen
                """, (username, password, now_iso))
            await self._db.execute("UPDATE sessions SET events_count = events_count + 1 WHERE id = ?", (session_id,))

        else:
            await self._db.execute("UPDATE sessions SET events_count = events_count + 1 WHERE id = ?", (session_id,))

        await self._db.commit()

    async def get_stats(self) -> Dict[str, Any]:
        """Returns high-level statistics for the dashboard."""
        async with self._db.execute("SELECT COUNT(*) FROM sessions") as cursor:
            total_sessions = (await cursor.fetchone())[0]

        async with self._db.execute("SELECT COUNT(DISTINCT ip) FROM sessions") as cursor:
            unique_ips = (await cursor.fetchone())[0]

        async with self._db.execute("SELECT SUM(downloads_count), SUM(commands_count) FROM sessions") as cursor:
            row = await cursor.fetchone()
            total_downloads = row[0] or 0
            total_commands = row[1] or 0

        # Top credentials
        top_creds = []
        async with self._db.execute("""
            SELECT username, password, count FROM credentials 
            ORDER BY count DESC LIMIT 10
        """) as cursor:
            async for r in cursor:
                top_creds.append({
                    "username": r["username"],
                    "password": r["password"],
                    "count": r["count"]
                })

        # Country distribution
        countries = []
        async with self._db.execute("""
            SELECT country_code as code, country, AVG(lat) as lat, AVG(lng) as lng, COUNT(*) as count 
            FROM sessions 
            WHERE country_code != 'UN' AND country_code != 'LAN'
            GROUP BY country_code 
            ORDER BY count DESC
        """) as cursor:
            async for r in cursor:
                countries.append({
                    "code": r["code"],
                    "count": r["count"],
                    "lat": r["lat"] or 0.0,
                    "lng": r["lng"] or 0.0
                })

        # 24-hour timeline histogram
        timeline = [0] * 24
        async with self._db.execute("""
            SELECT start_time FROM sessions 
            WHERE start_time >= datetime('now', '-24 hours')
        """) as cursor:
            async for r in cursor:
                try:
                    dt = datetime.fromisoformat(r["start_time"].replace("Z", "+00:00"))
                    diff_hours = int((datetime.now(timezone.utc) - dt).total_seconds() // 3600)
                    if 0 <= diff_hours < 24:
                        timeline[23 - diff_hours] += 1
                except Exception:
                    pass

        return {
            "totalSessions": total_sessions,
            "uniqueIPs": unique_ips,
            "totalDownloads": total_downloads,
            "totalCommands": total_commands,
            "topCredentials": top_creds,
            "timelineData": timeline,
            "countries": countries
        }

    async def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Returns all session summaries with classification matching cowrie_web."""
        sessions = []
        async with self._db.execute("""
            SELECT s.*,
                   (SELECT filename FROM downloads WHERE session_id = s.id LIMIT 1) as payload_file,
                   (SELECT json_extract(data_json, '$.input') FROM events WHERE session_id = s.id AND eventid = 'cowrie.command.input' AND json_extract(data_json, '$.input') NOT LIKE '%history%' ORDER BY id DESC LIMIT 1) as last_cmd,
                   (SELECT json_extract(data_json, '$.username') || ':' || COALESCE(json_extract(data_json, '$.password'), '') FROM events WHERE (session_id = s.id OR session_id = 'auth_' || replace(s.ip, '.', '_')) AND eventid = 'cowrie.login.success' LIMIT 1) as login_cred
            FROM sessions s
            ORDER BY s.start_time DESC LIMIT 1000
        """) as cursor:
            async for s in cursor:
                campaign = s["campaign"]
                dls = s["downloads_count"] or 0
                cmds = s["commands_count"] or 0
                cred = s["login_cred"]
                dur = s["duration"] or 0.0

                # Compute Interest Score (0 - 100)
                if dls > 0:
                    score = 95
                    threat_level = "critical"
                elif cmds >= 10:
                    score = 75 + min(15, int(cmds / 100))
                    threat_level = "high"
                elif cmds > 0 or cred:
                    score = 50 + min(15, cmds)
                    threat_level = "medium"
                else:
                    score = 15
                    threat_level = "low"

                session_type = "downloader" if dls > 0 else ("interactive" if cmds >= 5 else ("scanner" if cmds > 0 else "bruteforce"))

                sessions.append({
                    "id": s["id"],
                    "ip": s["ip"],
                    "port": s["port"],
                    "country": s["country"],
                    "countryCode": s["country_code"],
                    "duration": dur,
                    "threatLevel": threat_level,
                    "score": score,
                    "eventsCount": s["events_count"],
                    "commandsCount": cmds,
                    "downloadsCount": dls,
                    "payloadFile": s["payload_file"],
                    "lastCommand": s["last_cmd"],
                    "loginCred": cred,
                    "campaign": campaign,
                    "type": session_type,
                    "startTime": s["start_time"]
                })
        return sessions

    async def get_session_by_id(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Returns full session object with event array and downloads."""
        async with self._db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)) as cursor:
            s = await cursor.fetchone()
        if not s:
            return None

        events = []
        commands = []
        downloads = []

        async with self._db.execute("""
            SELECT data_json FROM events WHERE session_id = ? ORDER BY timestamp ASC
        """, (session_id,)) as cursor:
            async for r in cursor:
                try:
                    ev = json.loads(r["data_json"])
                    events.append(ev)
                    if ev.get("eventid") == "cowrie.command.input":
                        commands.append(ev.get("input", ""))
                except Exception:
                    pass

        async with self._db.execute("""
            SELECT * FROM downloads WHERE session_id = ? ORDER BY timestamp ASC
        """, (session_id,)) as cursor:
            async for d in cursor:
                downloads.append({
                    "shasum": d["shasum"],
                    "filename": d["filename"],
                    "size": d["size"],
                    "url": d["url"],
                    "timestamp": d["timestamp"]
                })

        # Inject authentication details if stored under auth_<ip> or ip_auth_cache
        has_login = any("login" in ev.get("eventid", "") for ev in events)
        if not has_login:
            auth_sid = f"auth_{s['ip'].replace('.', '_')}"
            async with self._db.execute("SELECT data_json FROM events WHERE session_id = ? ORDER BY timestamp ASC", (auth_sid,)) as cursor:
                async for r in cursor:
                    try:
                        ev = json.loads(r["data_json"])
                        events.insert(0, ev)
                    except Exception:
                        pass
            if not any("login" in ev.get("eventid", "") for ev in events):
                async with self._db.execute("SELECT locked_username, locked_password FROM ip_auth_cache WHERE ip = ?", (s["ip"],)) as cursor:
                    cache_row = await cursor.fetchone()
                    if cache_row and cache_row[0]:
                        events.insert(0, {
                            "eventid": "cowrie.login.success",
                            "username": cache_row[0],
                            "password": cache_row[1] or "",
                            "timestamp": s["start_time"],
                            "message": f"Login: {cache_row[0]}:{cache_row[1] or ''}"
                        })

        # Calculate accurate duration if recorded as 0.0
        duration = s["duration"]
        if duration <= 0.0:
            if len(events) >= 2:
                try:
                    from datetime import datetime
                    t1 = datetime.fromisoformat(events[0]["timestamp"])
                    t2 = datetime.fromisoformat(events[-1]["timestamp"])
                    duration = max(0.0, round((t2 - t1).total_seconds(), 2))
                except Exception:
                    pass
            if duration <= 0.0 and s["start_time"] and s["updated_at"]:
                try:
                    from datetime import datetime
                    t1 = datetime.fromisoformat(s["start_time"])
                    t2 = datetime.fromisoformat(s["updated_at"])
                    duration = max(0.0, round((t2 - t1).total_seconds(), 2))
                except Exception:
                    pass

        return {
            "id": s["id"],
            "ip": s["ip"],
            "port": s["port"],
            "country": s["country"],
            "countryCode": s["country_code"],
            "duration": duration,
            "threatLevel": s["threat_level"],
            "events": events,
            "downloads": downloads,
            "commands": commands,
            "downloadsCount": s["downloads_count"],
            "commandsCount": len(commands) if len(commands) > s["commands_count"] else s["commands_count"],
            "startTime": s["start_time"]
        }

    async def get_live_events(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Returns recent events mapped for the live feed."""
        events = []
        async with self._db.execute("""
            SELECT e.eventid, e.timestamp, e.data_json, s.ip, s.country_code 
            FROM events e 
            JOIN sessions s ON e.session_id = s.id 
            ORDER BY e.timestamp DESC LIMIT ?
        """, (limit,)) as cursor:
            async for r in cursor:
                try:
                    data = json.loads(r["data_json"])
                    ev_id = r["eventid"]
                    src_ip = r["ip"]
                    country = r["country_code"] or "UN"
                    
                    type_str = "connect"
                    detail = f"Connection from {src_ip}"
                    badge = "connect"

                    if "login.success" in ev_id:
                        type_str = "login"
                        badge = "login"
                        detail = f"Successful login: {data.get('username')}"
                    elif "login.failed" in ev_id:
                        type_str = "auth"
                        badge = "login"
                        detail = f"Failed login: {data.get('username')}"
                    elif "command" in ev_id:
                        type_str = "command"
                        badge = "command"
                        detail = f"Command: {data.get('input', '')}"
                    elif "download" in ev_id:
                        type_str = "download"
                        badge = "download"
                        detail = f"Downloaded: {data.get('url') or data.get('shasum') or 'file'}"

                    events.append({
                        "type": type_str,
                        "badgeClass": badge,
                        "detail": detail,
                        "timestamp": r["timestamp"],
                        "country": country
                    })
                except Exception:
                    pass

        return events

    async def get_all_downloads(self, limit: int = 50) -> List[Dict[str, Any]]:
        downloads = []
        async with self._db.execute("""
            SELECT d.id, d.session_id, d.shasum, d.filename, d.size, d.url, d.saved_path, d.timestamp, s.ip, s.country_code
            FROM downloads d
            LEFT JOIN sessions s ON d.session_id = s.id
            ORDER BY d.id DESC LIMIT ?
        """, (limit,)) as cursor:
            async for r in cursor:
                downloads.append({
                    "id": r["id"],
                    "sessionId": r["session_id"],
                    "shasum": r["shasum"],
                    "filename": r["filename"],
                    "size": r["size"],
                    "url": r["url"],
                    "savedPath": r["saved_path"],
                    "timestamp": r["timestamp"],
                    "ip": r["ip"],
                    "countryCode": r["country_code"]
                })
        return downloads
