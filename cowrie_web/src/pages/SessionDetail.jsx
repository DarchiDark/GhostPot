import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, GitBranch, Wifi, LogIn, XCircle, TerminalSquare,
  Download, Power, Clock, Globe, KeyRound, Server, GripVertical, Loader2,
  RefreshCw, ShieldAlert, Key
} from 'lucide-react';
import { getSessionById } from '../data';

function formatDuration(sec) {
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60), s = sec % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

const EVENT_CONFIG = {
  'cowrie.session.connect':       { color: '#10b981', label: 'Connection',      Icon: Wifi },
  'cowrie.login.failed':          { color: '#f72585', label: 'Auth Failure',     Icon: XCircle },
  'cowrie.login.success':         { color: '#3b82f6', label: 'Auth Success',     Icon: LogIn },
  'cowrie.command.input':         { color: '#f59e0b', label: 'Command Run',      Icon: TerminalSquare },
  'cowrie.command.failed':        { color: '#f59e0b', label: 'Command Failed',   Icon: TerminalSquare },
  'cowrie.session.file_download': { color: '#f72585', label: 'Payload Download', Icon: Download },
  'cowrie.session.closed':        { color: '#6b7280', label: 'Session Closed',   Icon: Power },
  'system.pattern':               { color: '#8b5cf6', label: 'Repeating Pattern', Icon: RefreshCw },
};

const CARD_W = 260;
const CARD_H_EST = 130;
const GAP_X = 80;
const GAP_Y = 60;
const PAD_LEFT = 40;
const PAD_TOP = 20;

function computeInitialPositions(count, containerWidth) {
  const cols = Math.max(1, Math.floor((containerWidth - PAD_LEFT) / (CARD_W + GAP_X)));
  return Array.from({ length: count }, (_, i) => ({
    x: PAD_LEFT + (i % cols) * (CARD_W + GAP_X),
    y: PAD_TOP + Math.floor(i / cols) * (CARD_H_EST + GAP_Y),
  }));
}

/* ---- SVG arrow overlay ---- */
function ArrowOverlay({ positions, wrapperRef }) {
  const lines = [];
  for (let i = 0; i < positions.length - 1; i++) {
    const from = positions[i];
    const to = positions[i + 1];

    const fromEl = wrapperRef.current?.querySelector(`[data-card-index="${i}"]`);
    const toEl = wrapperRef.current?.querySelector(`[data-card-index="${i + 1}"]`);
    const fromW = fromEl?.offsetWidth || CARD_W;
    const fromH = fromEl?.offsetHeight || CARD_H_EST;
    const toH = toEl?.offsetHeight || CARD_H_EST;

    const x1 = from.x + fromW + 4;
    const y1 = from.y + fromH / 2;
    const x2 = to.x - 4;
    const y2 = to.y + toH / 2;

    const midX = (x1 + x2) / 2;

    lines.push(
      <g key={i}>
        <path
          d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
          fill="none" stroke="rgba(255,255,255,0.12)" strokeWidth="2" strokeDasharray="6 4"
        />
        <polygon
          points={`${x2},${y2} ${x2 - 8},${y2 - 5} ${x2 - 8},${y2 + 5}`}
          fill="rgba(255,255,255,0.25)"
        />
        <circle cx={x1} cy={y1} r="3" fill="rgba(0,245,212,0.5)" />
      </g>
    );
  }

  let maxX = 0, maxY = 0;
  positions.forEach((p, i) => {
    const el = wrapperRef.current?.querySelector(`[data-card-index="${i}"]`);
    const w = el?.offsetWidth || CARD_W;
    const h = el?.offsetHeight || CARD_H_EST;
    maxX = Math.max(maxX, p.x + w + 40);
    maxY = Math.max(maxY, p.y + h + 40);
  });

  return (
    <svg
      width={maxX} height={maxY}
      style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none', zIndex: 0 }}
    >
      {lines}
    </svg>
  );
}

/* ---- Event Card ---- */
function EventCard({ event, session, x, y, index, onGripMouseDown, isDragging, onShowToast }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = EVENT_CONFIG[event.eventid] || { color: '#6b7280', label: `Unknown: ${event.eventid}`, Icon: Power };
  const { color, label, Icon } = cfg;
  const timeStr = new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const handleCopy = (e, text) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    if (onShowToast) onShowToast(`Copied: ${text.substring(0, 30)}${text.length > 30 ? '...' : ''}`);
  };

  let bodyContent = null;
  let details = [];

  switch (event.eventid) {
    case 'cowrie.session.connect':
      bodyContent = <div>From <span className="mono">{event.src_ip}</span> → port <span className="mono">{event.dst_port}</span></div>;
      details = [['Timestamp', event.timestamp], ['Origin', event.country || session.country], ['Sensor', 'cowrie-node-01']];
      break;
    case 'cowrie.login.failed':
      bodyContent = <div>Failed: <span className="mono" style={{ color: '#f72585', fontWeight: 700 }}>{esc(event.username)}:{esc(event.password)}</span></div>;
      details = [['Timestamp', event.timestamp], ['Username', event.username], ['Password', event.password]];
      break;
    case 'cowrie.login.success':
      bodyContent = <div>Success: <span className="mono" style={{ color: '#00f5d4', fontWeight: 700 }}>{esc(event.username)}:{esc(event.password)}</span></div>;
      details = [['Timestamp', event.timestamp], ['Username', event.username], ['Password', event.password]];
      break;
    case 'cowrie.command.input':
      bodyContent = <code className="chain-cmd" onClick={(e) => handleCopy(e, event.input)} title="Click to copy">{esc(event.input)}</code>;
      details = [['Timestamp', event.timestamp], ['Working Dir', '/tmp'], ['Status', 'Emulated']];
      break;
    case 'cowrie.command.failed':
      bodyContent = (
        <>
          <code className="chain-cmd" style={{ color: '#f72585', borderColor: 'rgba(247,37,133,0.3)' }} onClick={(e) => handleCopy(e, event.input)} title="Click to copy">{esc(event.input)}</code>
          {expanded && event.message && <div style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: '#f72585' }}>{esc(event.message)}</div>}
        </>
      );
      details = [['Timestamp', event.timestamp], ['Error', event.message || 'Not found']];
      break;
    case 'cowrie.session.file_download':
      bodyContent = (
        <>
          <div style={{ fontWeight: 500, color: '#f72585', marginBottom: '0.25rem' }}>Payload Downloaded</div>
          <div className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', wordBreak: 'break-all', background: 'rgba(0,0,0,0.2)', padding: '0.25rem', borderRadius: 4 }}>
            {esc(event.url || event.outfile || event.shasum || 'Unknown source')}
          </div>
        </>
      );
      details = [['Timestamp', event.timestamp], ['URL', event.url], ['Saved As', event.outfile], ['SHA256', event.shasum]];
      break;
    case 'cowrie.session.closed':
      bodyContent = <div>Disconnected ({event.duration}s)</div>;
      details = [['Timestamp', event.timestamp], ['Reason', 'Closed by remote']];
      break;
    case 'system.pattern':
      bodyContent = (
        <div style={{ color: 'var(--color-purple)', fontWeight: 600, padding: '0.2rem 0', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div>Collapsed {event.repeats} identical loops</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Pattern: {event.events.map(e => e.eventid.replace('cowrie.', '')).join(' → ')}
          </div>
        </div>
      );
      details = [['Hidden Events', event.patternLength * event.repeats]];
      break;
    default: 
      bodyContent = <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>{esc(event.message || JSON.stringify(event))}</div>;
      details = [['Timestamp', event.timestamp]];
      break;
  }

  return (
    <div
      className={`chain-card-abs ${expanded ? 'expanded' : ''}`}
      style={{ '--node-color': color, left: x, top: y, zIndex: isDragging ? 50 : 1 }}
      data-card-index={index}
      onClick={() => { if (!isDragging) setExpanded(!expanded); }}
    >
      <div className="chain-card-grip" onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); onGripMouseDown(index, e); }}>
        <GripVertical size={14} />
        <span className="chain-card-order">#{index + 1}</span>
      </div>
      <div className="chain-card-header">
        <div className="chain-card-type"><Icon size={14} /> {label}</div>
        <div className="chain-card-time">{timeStr}</div>
      </div>
      <div className="chain-card-body">{bodyContent}</div>
      <div className="chain-card-details">
        {details.map(([lbl, val], i) => (
          <div className="chain-detail-row" key={i}>
            <span className="chain-detail-lbl">{lbl}</span>
            <span className="chain-detail-val">{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---- Main page ---- */
export default function SessionDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [toast, setToast] = useState(null);
  
  const wrapperRef = useRef(null);
  const dragState = useRef({ active: false, index: -1, startX: 0, startY: 0, origX: 0, origY: 0, moved: false });
  const [draggingIdx, setDraggingIdx] = useState(-1);
  const [positions, setPositions] = useState([]);
  const initialized = useRef(false);

  const showToast = useCallback((msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2500);
  }, []);

  const credentials = useMemo(() => {
    if (!session) return [];
    const creds = new Set();
    session.events.forEach(e => {
      if (e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success') {
        const u = e.username || 'root';
        const p = e.password !== undefined && e.password !== null ? (e.password === "" ? '"" (empty)' : e.password) : '"" (empty)';
        creds.add(`${u}:${p}`);
      }
    });
    return Array.from(creds);
  }, [session]);

  const displayEvents = useMemo(() => {
    if (!session) return [];
    const ignored = new Set([
      'cowrie.client.kex', 
      'cowrie.client.version', 
      'cowrie.client.fingerprint', 
      'cowrie.session.params', 
      'cowrie.log.closed',
      'cowrie.client.size',
      'cowrie.direct-tcpip.request'
    ]);
    const filtered = session.events.filter(e => !ignored.has(e.eventid));
    
    // Collapse repeating patterns
    const result = [];
    let i = 0;
    
    const getSig = (e) => {
      if (e.eventid === 'cowrie.command.input' || e.eventid === 'cowrie.command.failed') return `${e.eventid}:${e.input}`;
      // Aggressively group login attempts regardless of what username/password is used
      if (e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success') return `${e.eventid}`;
      if (e.eventid === 'cowrie.session.file_download') return `${e.eventid}:${e.url || e.shasum}`;
      return e.eventid;
    };
    
    while (i < filtered.length) {
      let bestPatternLen = 0;
      let bestRepeatCount = 0;
      
      for (let pLen = 1; pLen <= 10 && i + pLen * 2 <= filtered.length; pLen++) {
        const pattern = filtered.slice(i, i + pLen).map(getSig).join('|');
        let repeats = 1;
        
        let j = i + pLen;
        while (j + pLen <= filtered.length) {
          const nextPattern = filtered.slice(j, j + pLen).map(getSig).join('|');
          if (nextPattern === pattern) {
            repeats++;
            j += pLen;
          } else {
            break;
          }
        }
        
        if (repeats > 1 && repeats * pLen > bestPatternLen * bestRepeatCount) {
          bestPatternLen = pLen;
          bestRepeatCount = repeats;
        }
      }
      
      if (bestRepeatCount > 1) {
        // Emitting the first iteration of the pattern normally
        for (let k = 0; k < bestPatternLen; k++) {
          result.push(filtered[i + k]);
        }
        
        // Emitting the "system.pattern" block for the REST of the repeats
        result.push({
          eventid: 'system.pattern',
          patternLength: bestPatternLen,
          repeats: bestRepeatCount - 1,
          events: filtered.slice(i, i + bestPatternLen),
          timestamp: filtered[i + bestPatternLen].timestamp,
          duration: 0
        });
        i += bestPatternLen * bestRepeatCount;
      } else {
        result.push(filtered[i]);
        i++;
      }
    }
    return result;
  }, [session]);

  useEffect(() => {
    async function fetchSession() {
      try {
        const data = await getSessionById(id);
        setSession(data);
      } catch (e) {
        console.error(e);
        setError(true);
      } finally {
        setLoading(false);
      }
    }
    fetchSession();
  }, [id]);

  // Initial layout once loaded
  useEffect(() => {
    if (!session || initialized.current) return;
    const el = wrapperRef.current;
    if (!el) return;
    setPositions(computeInitialPositions(displayEvents.length, el.clientWidth));
    initialized.current = true;
  }, [session, displayEvents.length]);

  // Re-layout on resize
  useEffect(() => {
    if (!session) return;
    const onResize = () => {
      if (!wrapperRef.current) return;
      setPositions(computeInitialPositions(displayEvents.length, wrapperRef.current.clientWidth));
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [session, displayEvents.length]);

  const onGripMouseDown = useCallback((index, e) => {
    const pos = positions[index];
    dragState.current = { active: true, index, startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y, moved: false };
    setDraggingIdx(index);

    const onMove = (ev) => {
      if (!dragState.current.active) return;
      const dx = ev.clientX - dragState.current.startX;
      const dy = ev.clientY - dragState.current.startY;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragState.current.moved = true;
      setPositions(prev => {
        const next = [...prev];
        next[dragState.current.index] = { x: dragState.current.origX + dx, y: dragState.current.origY + dy };
        return next;
      });
    };

    const onUp = () => {
      dragState.current.active = false;
      setDraggingIdx(-1);
      setTimeout(() => { dragState.current.moved = false; }, 0);
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }, [positions]);

  if (loading) {
    return (
      <div className="session-detail-page" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', flexDirection: 'column' }}>
        <Loader2 className="animate-spin" size={48} style={{ color: 'var(--color-cyan)', marginBottom: '1rem' }} />
        <h2 style={{ color: 'var(--text-secondary)' }}>Decrypting session stream...</h2>
      </div>
    );
  }

  if (error || !session) {
    return (
      <div className="session-detail-page" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
        <div style={{ textAlign: 'center' }}>
          <h2 style={{ marginBottom: '1rem' }}>Session not found or error loading</h2>
          <button className="back-btn" onClick={() => navigate('/sessions')}><ArrowLeft size={16}/> Back to Sessions</button>
        </div>
      </div>
    );
  }

  const successLogin = session.events.find(e => e.eventid === 'cowrie.login.success');
  const failedLogins = session.events.filter(e => e.eventid === 'cowrie.login.failed');

  return (
    <div className="session-detail-page">
      {/* Top Bar */}
      <div className="detail-topbar">
        <button className="back-btn" onClick={() => navigate('/sessions')}>
          <ArrowLeft size={16} /> Back to Cluster
        </button>
        <div className="detail-topbar-info">
          <h1>SESSION: {session.ip}</h1>
          <p>ID: {session.id}</p>
        </div>
        <div className="detail-topbar-badges">
          <span className={`threat-badge ${session.threatLevel}`}>{session.threatLevel} threat</span>
        </div>
      </div>

      {/* Meta Grid */}
      <div className="detail-meta-grid">
        <div className="meta-box">
          <div className="meta-box-label"><Globe size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />Origin</div>
          <div className="meta-box-val">{session.country} ({session.countryCode})</div>
        </div>
        <div className="meta-box">
          <div className="meta-box-label"><Clock size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />Duration</div>
          <div className="meta-box-val">{formatDuration(session.duration)}</div>
        </div>
        <div className="meta-box">
          <div className="meta-box-label"><KeyRound size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />Authentication</div>
          <div className="meta-box-val">
            {successLogin ? (
              <span style={{ color: 'var(--color-emerald)' }}>{successLogin.username || 'root'}:{successLogin.password ? successLogin.password : '"" (empty)'}</span>
            ) : failedLogins.length > 0 ? (
              <span style={{ color: 'var(--color-pink)' }}>Failed ({failedLogins.length} attempts)</span>
            ) : 'No login attempt'}
          </div>
        </div>
        <div className="meta-box">
          <div className="meta-box-label"><Server size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />Honeypot Port</div>
          <div className="meta-box-val">Port {session.port}</div>
        </div>
        <div className="meta-box">
          <div className="meta-box-label"><TerminalSquare size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />Commands</div>
          <div className="meta-box-val">{session.commandsCount} executed</div>
        </div>
        <div className="meta-box">
          <div className="meta-box-label"><Download size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />Downloads</div>
          <div className="meta-box-val">{session.downloadsCount} payloads</div>
        </div>
      </div>

      {/* Main Content Split */}
      <div style={{ display: 'flex', gap: '1.5rem', padding: '0 2rem 2rem', alignItems: 'flex-start' }}>
        
        {/* Left Sidebar (Credentials) */}
        <div style={{ width: '280px', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="card" style={{ padding: '1.25rem' }}>
            <div className="card-title" style={{ fontSize: '0.85rem' }}><Key size={16} /> Extracted Credentials</div>
            {credentials.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '500px', overflowY: 'auto', paddingRight: '0.5rem' }}>
                {credentials.map((cred, i) => (
                  <div key={i} className="mono" style={{ 
                    fontSize: '0.8rem', padding: '0.5rem', 
                    background: 'rgba(0,0,0,0.3)', borderRadius: '6px', 
                    border: '1px solid rgba(255,255,255,0.05)',
                    color: 'var(--text-primary)', wordBreak: 'break-all'
                  }}>
                    {cred}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No credentials captured.</div>
            )}
          </div>
          
          <div className="card" style={{ padding: '1.25rem' }}>
             <div className="card-title" style={{ fontSize: '0.85rem' }}><ShieldAlert size={16} /> Session Notes</div>
             <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                This IP triggered <strong>{session.events.length}</strong> events across {session.sessionIds?.length || 1} connections.
             </div>
          </div>
        </div>

        {/* Draggable Event Chain */}
        <div className="chain-section" style={{ flex: 1, padding: 0 }}>
          <div className="chain-section-title">
            <GitBranch size={18} /> Attack Event Chain
            <span style={{ fontSize: '0.75rem', fontWeight: 400, color: 'var(--text-muted)', marginLeft: 'auto', textTransform: 'none' }}>
              Drag blocks to rearrange • Click to expand details
            </span>
          </div>

          <div className="chain-canvas-wrapper" ref={wrapperRef}>
            {positions.length > 0 && (
              <>
                <ArrowOverlay positions={positions} wrapperRef={wrapperRef} />
                {displayEvents.map((event, idx) => (
                  <EventCard
                    key={idx}
                    event={event}
                    session={session}
                    x={positions[idx]?.x ?? 0}
                    y={positions[idx]?.y ?? 0}
                    index={idx}
                    onGripMouseDown={onGripMouseDown}
                    isDragging={draggingIdx === idx || dragState.current.moved}
                    onShowToast={showToast}
                  />
                ))}
              </>
            )}
          </div>
        </div>

      </div>

      {toast && (
        <div className="toast-notification">
          {toast}
        </div>
      )}
    </div>
  );
}
