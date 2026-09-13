import express from 'express';
import cors from 'cors';
import fs from 'fs';
import readline from 'readline';
import geoip from 'geoip-lite';
import path from 'path';
import crypto from 'crypto';

const app = express();
app.use(cors());

const LOG_FILE = path.resolve('cowrie.json');

// In-memory store for parsed data
let sessionsMap = new Map();
let globalStats = {
  totalSessions: 0,
  uniqueIPs: new Set(),
  totalDownloads: 0,
  totalCommands: 0,
  topCredentials: new Map(),
  timeline: Array(24).fill(0),
};

// ----------------------------------------------------
// FULL PARSER (Called once on startup and every 2 mins)
// ----------------------------------------------------
function parseLogFile() {
  console.log(`[FULL PARSE] Reading logs from ${LOG_FILE}...`);
  if (!fs.existsSync(LOG_FILE)) {
    console.error('Log file not found!');
    return;
  }

  sessionsMap.clear();
  globalStats.uniqueIPs.clear();
  globalStats.topCredentials.clear();
  globalStats.totalSessions = 0;
  globalStats.totalDownloads = 0;
  globalStats.totalCommands = 0;

  const sessionToIp = new Map();
  let maxTimeMs = 0;

  const rl = readline.createInterface({
    input: fs.createReadStream(LOG_FILE),
    crlfDelay: Infinity
  });

  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      const event = JSON.parse(line);
      const sessionId = event.session;
      if (!sessionId) return;

      if (event.src_ip) {
        sessionToIp.set(sessionId, event.src_ip);
      }
      
      const ip = event.src_ip || sessionToIp.get(sessionId) || 'unknown';

      if (!sessionsMap.has(ip)) {
        sessionsMap.set(ip, {
          id: ip,
          ip: ip,
          port: event.dst_port || 2222,
          country: 'Unknown',
          countryCode: 'UN',
          duration: 0,
          threatLevel: 'low',
          events: [],
          downloads: [],
          commands: [],
          downloadsCount: 0,
          commandsCount: 0,
          startTime: event.timestamp || new Date().toISOString()
        });
      }

      const session = sessionsMap.get(ip);
      
      if (session.events.length < 150) {
        session.events.push(event);
      } else if (!session.truncated) {
        session.events.push({ 
          eventid: 'system.truncated', 
          timestamp: event.timestamp, 
          message: 'Further events from this IP were truncated to save resources.' 
        });
        session.truncated = true;
      }

      if (ip !== 'unknown') {
        globalStats.uniqueIPs.add(ip);
        if (session.countryCode === 'UN') {
          const geo = geoip.lookup(ip);
          if (geo) {
            session.countryCode = geo.country;
            session.country = geo.country;
          }
        }
      }
      if (event.dst_port) session.port = event.dst_port;

      if (event.timestamp) {
        const ts = new Date(event.timestamp).getTime();
        if (ts > maxTimeMs) maxTimeMs = ts;
      }

      switch (event.eventid) {
        case 'cowrie.session.closed':
          session.duration += parseFloat(event.duration) || 0;
          break;
        case 'cowrie.command.input':
          session.commands.push(event.input);
          session.commandsCount++;
          globalStats.totalCommands++;
          session.threatLevel = session.threatLevel === 'high' ? 'high' : 'medium';
          break;
        case 'cowrie.session.file_download':
          session.downloads.push(event);
          session.downloadsCount++;
          globalStats.totalDownloads++;
          session.threatLevel = 'high';
          break;
        case 'cowrie.login.success':
        case 'cowrie.login.failed':
          if (event.username) {
            const cred = `${event.username}:${event.password || event.key || '<empty>'}`;
            const count = globalStats.topCredentials.get(cred) || 0;
            globalStats.topCredentials.set(cred, count + 1);
          }
          break;
      }
    } catch (e) {}
  });

  rl.on('close', () => {
    globalStats.totalSessions = sessionsMap.size;
    console.log(`[FULL PARSE] Loaded ${globalStats.totalSessions} unique IP sessions.`);
    
    globalStats.timeline = Array(24).fill(0);
    const ONE_HOUR = 3600000;
    
    for (const session of sessionsMap.values()) {
      session.events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      const t = new Date(session.startTime).getTime();
      const diffHours = Math.floor((maxTimeMs - t) / ONE_HOUR);
      if (diffHours >= 0 && diffHours < 24) {
        globalStats.timeline[23 - diffHours]++;
      }
    }
  });
}

parseLogFile();
setInterval(() => {
  console.log('--- Scheduled Update: Refreshing Full Data ---');
  parseLogFile();
}, 2 * 60 * 1000);

// ----------------------------------------------------
// LIGHTWEIGHT TAIL FOR LIVE FEED
// ----------------------------------------------------
const liveEventsBuffer = [];
let lastFileSize = 0;

function tailLogFile() {
  if (!fs.existsSync(LOG_FILE)) return;
  const stats = fs.statSync(LOG_FILE);
  
  if (lastFileSize === 0 && stats.size > 0) {
    // On first run, just set the file size, don't read the whole 3MB for the live feed
    lastFileSize = stats.size;
    return;
  }

  if (stats.size > lastFileSize) {
    const stream = fs.createReadStream(LOG_FILE, { start: lastFileSize, end: stats.size - 1 });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    rl.on('line', (line) => {
      try {
        const e = JSON.parse(line);
        if (e.eventid) {
          liveEventsBuffer.push(e);
          if (liveEventsBuffer.length > 30) liveEventsBuffer.shift(); // Keep only 30 most recent
        }
      } catch (err) {}
    });
    rl.on('close', () => {
      lastFileSize = stats.size;
    });
  } else if (stats.size < lastFileSize) {
    lastFileSize = 0; // File was rotated
  }
}
setInterval(tailLogFile, 2000);


// ----------------------------------------------------
// API ENDPOINTS
// ----------------------------------------------------
app.get('/api/stats', (req, res) => {
  const countryCounts = {};
  for (const session of sessionsMap.values()) {
    if (session.countryCode !== 'UN') {
      countryCounts[session.countryCode] = (countryCounts[session.countryCode] || 0) + 1;
    }
  }
  
  const countries = Object.entries(countryCounts)
    .map(([code, count]) => {
      let lat = 0, lng = 0;
      for (const s of sessionsMap.values()) {
        if (s.countryCode === code) {
          const g = geoip.lookup(s.ip);
          if (g && g.ll) {
            lat = g.ll[0];
            lng = g.ll[1];
            break;
          }
        }
      }
      return { code, count, lat, lng };
    })
    .sort((a, b) => b.count - a.count);

  const topCreds = Array.from(globalStats.topCredentials.entries())
    .map(([cred, count]) => {
      const [username, password] = cred.split(':');
      return { username, password: password === '<empty>' ? '' : password, count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  res.json({
    totalSessions: globalStats.totalSessions,
    uniqueIPs: globalStats.uniqueIPs.size,
    totalDownloads: globalStats.totalDownloads,
    totalCommands: globalStats.totalCommands,
    topCredentials: topCreds,
    timelineData: globalStats.timeline,
    countries: countries
  });
});

app.get('/api/sessions', (req, res) => {
  const all = Array.from(sessionsMap.values()).map(s => {
    let campaign = 'Port Scanner';
    const allCmds = s.commands.join(' ');
    
    const sshRsaMatch = allCmds.match(/ssh-rsa\s+([A-Za-z0-9+\/]+)/);
    if (sshRsaMatch) {
      const hash = crypto.createHash('sha256').update(sshRsaMatch[1]).digest('hex').substring(0, 6);
      campaign = `SSH Key Injector (${hash})`;
    } else if (allCmds.match(/(arm|mips|x86|m68k|sparc|sh4)/i) || allCmds.includes('mirai') || allCmds.includes('gafgyt')) {
      const urlMatch = allCmds.match(/(?:wget|curl)[^\w]+(?:http:\/\/\/?)?([^\s]+)/i);
      campaign = urlMatch ? `IoT Botnet [${urlMatch[1].substring(0, 15)}]` : 'IoT Botnet Variant';
    } else if (allCmds.includes('xmr') || allCmds.includes('minerd') || allCmds.includes('kswapd0') || allCmds.includes('xmrig')) {
      campaign = 'Cryptominer';
    } else if (s.downloads.length > 0) {
      const d = s.downloads[0];
      campaign = d.shasum ? `Payload Dropper (${d.shasum.substring(0, 6)})` : 'Payload Dropper';
    } else if (allCmds.includes('uname') || allCmds.includes('cpuinfo') || allCmds.includes('lscpu')) {
      campaign = 'Reconnaissance';
    } else if (s.commands.length > 0) {
      const cmdStr = allCmds.replace(/\d+\.\d+\.\d+\.\d+/g, 'IP').replace(/\b\d+\b/g, 'N');
      const hash = crypto.createHash('sha256').update(cmdStr).digest('hex').substring(0, 6);
      campaign = `Custom Exploit (${hash})`;
    } else if (s.events.some(e => e.eventid === 'cowrie.login.failed')) {
      campaign = 'Bruteforce Campaign';
    }

    return {
      id: s.id,
      ip: s.ip,
      port: s.port,
      country: s.country,
      countryCode: s.countryCode,
      duration: s.duration,
      threatLevel: s.threatLevel,
      eventsCount: s.events.length,
      commandsCount: s.commandsCount,
      downloadsCount: s.downloadsCount,
      campaign: campaign,
      type: s.threatLevel === 'high' ? 'downloader' : (s.threatLevel === 'medium' ? 'interactive' : 'scanner')
    };
  });
  res.json(all);
});

app.get('/api/sessions/:id', (req, res) => {
  const session = sessionsMap.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Not found' });
  res.json(session);
});

app.get('/api/live', (req, res) => {
  // Use the tail buffer if it has data
  let recentEvents = [...liveEventsBuffer];
  
  // Fallback to end of sessionsMap if no live tail data yet (e.g. on first load)
  if (recentEvents.length === 0) {
    const sessions = Array.from(sessionsMap.values());
    for (let i = sessions.length - 1; i >= Math.max(0, sessions.length - 5); i--) {
      recentEvents.push(...sessions[i].events);
    }
  }
  
  recentEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  
  const mapped = recentEvents.slice(0, 15).map(e => {
    let type = 'connect';
    let detail = `Connection from ${e.src_ip || 'unknown'}`;
    let badgeClass = 'connect';
    
    if (e.eventid.includes('login.success')) { type = 'login'; badgeClass = 'login'; detail = `Successful login: ${e.username}`; }
    else if (e.eventid.includes('login.failed')) { type = 'auth'; badgeClass = 'login'; detail = `Failed login: ${e.username}`; }
    else if (e.eventid.includes('command')) { type = 'command'; badgeClass = 'command'; detail = `Command: ${e.input}`; }
    else if (e.eventid.includes('download')) { type = 'download'; badgeClass = 'download'; detail = `Downloaded: ${e.url || e.shasum || 'file'}`; }

    return {
      type,
      badgeClass,
      detail,
      timestamp: e.timestamp,
      country: e.src_ip ? (geoip.lookup(e.src_ip)?.country || 'UN') : 'UN'
    };
  });
  
  res.json(mapped);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});
