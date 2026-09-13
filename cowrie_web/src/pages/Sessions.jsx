import { useEffect, useRef, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Search, Loader2, ShieldAlert, Terminal, DownloadCloud, 
  KeyRound, Clock, Globe, List, Network, ChevronRight, Layers
} from 'lucide-react';
import { getAllSessions } from '../data';

function formatDuration(sec) {
  if (!sec || sec < 1) return '<1s';
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60), s = Math.round(sec % 60);
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

function getNodeGroup(session, groupType) {
  if (groupType === 'type') return session.type || 'scanner';
  if (groupType === 'duration') {
    if (session.duration < 30) return 'short';
    if (session.duration <= 300) return 'medium';
    return 'long';
  }
  return session.downloadsCount > 0 ? 'with_files' : 'no_files';
}

const GROUP_CONFIGS = {
  type: {
    groups: ['downloader', 'interactive', 'scanner', 'bruteforce'],
    labels: { downloader: 'Malware Droppers', interactive: 'Interactive Attackers', scanner: 'Info Gatherers', bruteforce: 'Bruteforce Scanners' },
    positions: (w) => ({ downloader: 0.15, interactive: 0.38, scanner: 0.62, bruteforce: 0.85 }),
  },
  duration: {
    groups: ['short', 'medium', 'long'],
    labels: { short: 'Instant (<30s)', medium: 'Active (30s–5m)', long: 'Persistent (>5m)' },
    positions: (w) => ({ short: 0.2, medium: 0.5, long: 0.8 }),
  },
  files: {
    groups: ['with_files', 'no_files'],
    labels: { with_files: 'Payload Dropped', no_files: 'No Payloads' },
    positions: (w) => ({ with_files: 0.35, no_files: 0.65 }),
  },
};

export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState('list');
  const [activeTab, setActiveTab] = useState('all');
  const [sortBy, setSortBy] = useState('score');
  const [groupType, setGroupType] = useState('type');
  const [search, setSearch] = useState('');
  const [tooltip, setTooltip] = useState(null);
  
  const canvasRef = useRef(null);
  const nodesRef = useRef([]);
  const animRef = useRef(null);
  const hoveredRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchSessions() {
      try {
        const data = await getAllSessions();
        setSessions(data);
      } catch (e) {
        console.error('Failed to load sessions', e);
      } finally {
        setLoading(false);
      }
    }
    fetchSessions();
  }, []);

  const tabCounts = useMemo(() => {
    let payloads = 0, commands = 0, logins = 0;
    sessions.forEach(s => {
      if (s.downloadsCount > 0) payloads++;
      if (s.commandsCount > 0) commands++;
      if (s.loginCred) logins++;
    });
    return { all: sessions.length, payloads, commands, logins };
  }, [sessions]);

  const filteredSessions = useMemo(() => {
    let result = sessions.filter(s => {
      if (activeTab === 'payloads' && (!s.downloadsCount || s.downloadsCount === 0)) return false;
      if (activeTab === 'commands' && (!s.commandsCount || s.commandsCount === 0)) return false;
      if (activeTab === 'logins' && !s.loginCred) return false;

      if (search) {
        const q = search.toLowerCase();
        const ipMatch = s.ip.includes(q);
        const countryMatch = (s.country || '').toLowerCase().includes(q);
        const cmdMatch = (s.lastCommand || '').toLowerCase().includes(q);
        const payloadMatch = (s.payloadFile || '').toLowerCase().includes(q);
        const credMatch = (s.loginCred || '').toLowerCase().includes(q);
        if (!ipMatch && !countryMatch && !cmdMatch && !payloadMatch && !credMatch) return false;
      }
      return true;
    });

    result.sort((a, b) => {
      if (sortBy === 'score') return (b.score || 0) - (a.score || 0);
      if (sortBy === 'time') return new Date(b.startTime) - new Date(a.startTime);
      if (sortBy === 'commands') return (b.commandsCount || 0) - (a.commandsCount || 0);
      if (sortBy === 'duration') return (b.duration || 0) - (a.duration || 0);
      if (sortBy === 'downloads') return (b.downloadsCount || 0) - (a.downloadsCount || 0);
      return 0;
    });

    return result;
  }, [sessions, activeTab, search, sortBy]);

  useEffect(() => {
    if (loading || viewMode !== 'graph') return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.parentElement.clientWidth;
    const h = canvas.parentElement.clientHeight;

    const existingMap = {};
    nodesRef.current.forEach(n => { existingMap[n.id] = n; });

    nodesRef.current = filteredSessions.map(session => {
      const eventCount = session.eventsCount || 5;
      const r = Math.max(16, 12 + Math.sqrt(eventCount) * 3);
      const existing = existingMap[session.id];
      if (existing) { existing.session = session; existing.r = r; return existing; }
      return { id: session.id, session, r, x: w / 2 + (Math.random() - 0.5) * 100, y: h / 2 + (Math.random() - 0.5) * 100, vx: 0, vy: 0 };
    });
  }, [filteredSessions, loading, viewMode]);

  useEffect(() => {
    if (loading || viewMode !== 'graph') return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let running = true;
    let alpha = 1.0;

    const loop = () => {
      if (!running) return;
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.parentElement.clientWidth;
      const h = canvas.parentElement.clientHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const cfg = GROUP_CONFIGS[groupType] || GROUP_CONFIGS.type;
      const posRatios = cfg.positions(w);
      const centers = {};
      cfg.groups.forEach(g => { centers[g] = { x: posRatios[g] * w, y: h * 0.5, label: cfg.labels[g] }; });

      const nodes = nodesRef.current;

      if (alpha > 0.002) {
        nodes.forEach(node => {
          const gk = getNodeGroup(node.session, groupType);
          const center = centers[gk];
          if (center) {
            node.vx += (center.x - node.x) * 0.05 * alpha;
            node.vy += (center.y - node.y) * 0.05 * alpha;
          }
        });

        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            const na = nodes[i], nb = nodes[j];
            const dx = nb.x - na.x, dy = nb.y - na.y;
            const dist = Math.hypot(dx, dy) || 1;
            const minDist = na.r + nb.r + 6;
            if (dist < minDist) {
              const force = (minDist - dist) / dist * 0.5 * alpha;
              na.vx -= dx * force; na.vy -= dy * force;
              nb.vx += dx * force; nb.vy += dy * force;
            }
          }
        }

        nodes.forEach(node => {
          node.vx *= 0.85; node.vy *= 0.85;
          node.x += node.vx; node.y += node.vy;
          node.x = Math.max(node.r + 5, Math.min(w - node.r - 5, node.x));
          node.y = Math.max(node.r + 5, Math.min(h - node.r - 5, node.y));
        });

        alpha *= 0.985;
      }

      // Draw Group Labels
      Object.entries(centers).forEach(([gk, c]) => {
        ctx.fillStyle = 'rgba(255,255,255,0.06)';
        ctx.font = '700 13px var(--font-mono)';
        ctx.textAlign = 'center';
        ctx.fillText(c.label.toUpperCase(), c.x, 35);
      });

      // Draw Nodes
      nodes.forEach(node => {
        const isHovered = hoveredRef.current === node.id;
        const color = node.session.threatLevel === 'critical' ? '#f72585' :
                      node.session.threatLevel === 'high' ? '#f59e0b' :
                      node.session.threatLevel === 'medium' ? '#00f5d4' : '#3b82f6';

        ctx.save();
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.fillStyle = `${color}25`;
        ctx.fill();

        ctx.strokeStyle = isHovered ? '#ffffff' : color;
        ctx.lineWidth = isHovered ? 3 : 1.5;
        if (isHovered) { ctx.shadowColor = color; ctx.shadowBlur = 15; }
        ctx.stroke();

        ctx.fillStyle = '#ffffff';
        ctx.font = '600 10px var(--font-mono)';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.session.ip.split('.').slice(0, 2).join('.') + '..', node.x, node.y - 3);

        ctx.fillStyle = 'rgba(255,255,255,0.6)';
        ctx.font = '9px var(--font-sans)';
        ctx.fillText(`${node.session.commandsCount || 0} cmds`, node.x, node.y + 8);
        ctx.restore();
      });

      animRef.current = requestAnimationFrame(loop);
    };

    animRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animRef.current);
  }, [loading, viewMode, groupType]);

  const handleCanvasMouseMove = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    const hit = nodesRef.current.find(n => Math.hypot(n.x - x, n.y - y) <= n.r);

    if (hit) {
      hoveredRef.current = hit.id;
      canvas.style.cursor = 'pointer';
      setTooltip({ x: e.clientX + 15, y: e.clientY + 15, session: hit.session });
    } else {
      hoveredRef.current = null;
      canvas.style.cursor = 'default';
      setTooltip(null);
    }
  };

  const handleCanvasClick = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    const hit = nodesRef.current.find(n => Math.hypot(n.x - x, n.y - y) <= n.r);
    if (hit) navigate(`/sessions/${hit.id}`);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', color: 'var(--text-muted)' }}>
        <Loader2 className="animate-spin" size={32} style={{ marginBottom: '1rem', color: 'var(--color-cyan)' }} />
        <p>Loading threat triage matrix...</p>
      </div>
    );
  }

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Top Controls Bar */}
      <div style={{ 
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem',
        background: 'var(--bg-card)', padding: '1rem 1.5rem', borderRadius: '12px', border: '1px solid var(--border-color)'
      }}>
        
        {/* Left: Triage Tabs */}
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {[
            { id: 'all', label: 'All Sessions', count: tabCounts.all, Icon: Layers },
            { id: 'payloads', label: 'Payload Drops', count: tabCounts.payloads, Icon: DownloadCloud, color: 'var(--color-pink)' },
            { id: 'commands', label: 'Active Commands', count: tabCounts.commands, Icon: Terminal, color: 'var(--color-amber)' },
            { id: 'logins', label: 'Captured Logins', count: tabCounts.logins, Icon: KeyRound, color: 'var(--color-emerald)' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                padding: '0.5rem 0.85rem', borderRadius: '8px', border: '1px solid',
                fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer',
                background: activeTab === tab.id ? 'rgba(0, 245, 212, 0.12)' : 'rgba(255,255,255,0.02)',
                borderColor: activeTab === tab.id ? 'var(--color-cyan)' : 'var(--border-color)',
                color: activeTab === tab.id ? '#ffffff' : 'var(--text-secondary)',
                transition: 'all 0.2s ease'
              }}
            >
              <tab.Icon size={14} style={{ color: tab.color || (activeTab === tab.id ? 'var(--color-cyan)' : 'inherit') }} />
              {tab.label}
              <span style={{ 
                background: activeTab === tab.id ? 'var(--color-cyan)' : 'rgba(255,255,255,0.08)',
                color: activeTab === tab.id ? '#05070d' : 'var(--text-muted)',
                padding: '0.1rem 0.45rem', borderRadius: '10px', fontSize: '0.7rem', fontWeight: 700
              }}>
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        {/* Right: Search, Sort, View Toggle */}
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          
          {/* Search */}
          <div className="search-container">
            <Search size={15} />
            <input
              type="text"
              className="search-input"
              placeholder="Search IP, country, cmd, payload..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ width: '220px' }}
            />
          </div>

          {/* Sort Dropdown */}
          <select 
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
              color: 'var(--text-primary)', padding: '0.5rem 0.85rem', borderRadius: '8px',
              fontSize: '0.82rem', outline: 'none', cursor: 'pointer'
            }}
          >
            <option value="score">Sort: Interest Score 🔥</option>
            <option value="time">Sort: Newest First 🕒</option>
            <option value="commands">Sort: Most Commands ⌨️</option>
            <option value="duration">Sort: Longest Duration ⏱️</option>
            <option value="downloads">Sort: Most Payloads 💣</option>
          </select>

          {/* View Switcher Toggle */}
          <div style={{ display: 'flex', background: 'var(--bg-secondary)', padding: '3px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <button
              onClick={() => setViewMode('list')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.35rem',
                background: viewMode === 'list' ? 'var(--bg-card)' : 'transparent',
                color: viewMode === 'list' ? 'var(--color-cyan)' : 'var(--text-secondary)',
                border: viewMode === 'list' ? '1px solid var(--border-color)' : 'none',
                padding: '0.4rem 0.75rem', borderRadius: '6px', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600
              }}
            >
              <List size={14} /> List
            </button>
            <button
              onClick={() => setViewMode('graph')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.35rem',
                background: viewMode === 'graph' ? 'var(--bg-card)' : 'transparent',
                color: viewMode === 'graph' ? 'var(--color-cyan)' : 'var(--text-secondary)',
                border: viewMode === 'graph' ? '1px solid var(--border-color)' : 'none',
                padding: '0.4rem 0.75rem', borderRadius: '6px', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600
              }}
            >
              <Network size={14} /> Graph
            </button>
          </div>

        </div>

      </div>

      {/* Main Content Area */}
      {viewMode === 'list' ? (
        
        /* === RANKED INTEREST LIST VIEW === */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {filteredSessions.length === 0 ? (
            <div className="card" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
              <ShieldAlert size={36} style={{ marginBottom: '1rem', color: 'var(--color-amber)', opacity: 0.7 }} />
              <h3>No attack sessions match your filter criteria</h3>
              <p style={{ fontSize: '0.85rem', marginTop: '0.35rem' }}>Try clearing the search query or selecting "All Sessions".</p>
            </div>
          ) : (
            filteredSessions.map(session => {
              const threatClass = session.threatLevel || 'low';
              const isCritical = threatClass === 'critical';
              const isHigh = threatClass === 'high';

              return (
                <div 
                  key={session.id}
                  onClick={() => navigate(`/sessions/${session.id}`)}
                  className="card"
                  style={{
                    padding: '1.1rem 1.4rem', cursor: 'pointer',
                    display: 'flex', flexDirection: 'column', gap: '0.65rem',
                    borderLeft: `4px solid ${
                      isCritical ? 'var(--color-pink)' : 
                      isHigh ? 'var(--color-amber)' : 
                      threatClass === 'medium' ? 'var(--color-cyan)' : 'rgba(255,255,255,0.15)'
                    }`,
                    background: isCritical ? 'linear-gradient(90deg, rgba(247,37,133,0.06) 0%, var(--bg-card) 40%)' :
                                isHigh ? 'linear-gradient(90deg, rgba(245,158,11,0.04) 0%, var(--bg-card) 40%)' : 'var(--bg-card)',
                    transition: 'transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = 'translateY(-2px)';
                    e.currentTarget.style.borderColor = isCritical ? 'var(--color-pink)' : 'var(--color-cyan)';
                    e.currentTarget.style.boxShadow = '0 6px 20px rgba(0,0,0,0.3)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = 'none';
                    e.currentTarget.style.borderColor = 'var(--border-color)';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  {/* Card Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                    
                    {/* Left: Score Badge + IP + Location */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                      <span className={`threat-badge ${threatClass}`} style={{ fontSize: '0.72rem', padding: '0.2rem 0.6rem' }}>
                        {isCritical ? 'CRITICAL • 95' : isHigh ? `HIGH • ${session.score || 75}` : threatClass === 'medium' ? `MEDIUM • ${session.score || 50}` : 'LOW • 15'}
                      </span>
                      <span className="mono" style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {session.ip}
                      </span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <Globe size={13} style={{ color: 'var(--text-muted)' }} />
                        {session.country || 'Unknown'} ({session.countryCode || 'UN'})
                      </span>
                    </div>

                    {/* Right: Timing & Action */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <Clock size={13} />
                        {formatDuration(session.duration)}
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                        {new Date(session.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                      <span style={{ 
                        color: 'var(--color-cyan)', fontSize: '0.8rem', fontWeight: 600, 
                        display: 'flex', alignItems: 'center', gap: '0.25rem' 
                      }}>
                        Inspect <ChevronRight size={14} />
                      </span>
                    </div>

                  </div>

                  {/* Badges Strip */}
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap', fontSize: '0.75rem' }}>
                    
                    {session.payloadFile && (
                      <span style={{ 
                        background: 'rgba(247,37,133,0.15)', color: 'var(--color-pink)', border: '1px solid rgba(247,37,133,0.3)',
                        padding: '0.2rem 0.6rem', borderRadius: '6px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' 
                      }}>
                        <DownloadCloud size={12} /> Payload: {session.payloadFile}
                      </span>
                    )}

                    {session.commandsCount > 0 && (
                      <span style={{ 
                        background: 'rgba(245,158,11,0.12)', color: 'var(--color-amber)', border: '1px solid rgba(245,158,11,0.25)',
                        padding: '0.2rem 0.6rem', borderRadius: '6px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' 
                      }}>
                        <Terminal size={12} /> {session.commandsCount} Commands Executed
                      </span>
                    )}

                    {session.loginCred && (
                      <span style={{ 
                        background: 'rgba(0,245,212,0.1)', color: 'var(--color-emerald)', border: '1px solid rgba(0,245,212,0.25)',
                        padding: '0.2rem 0.6rem', borderRadius: '6px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' 
                      }}>
                        <KeyRound size={12} /> Auth: {session.loginCred}
                      </span>
                    )}

                    <span style={{ 
                      background: 'rgba(255,255,255,0.04)', color: 'var(--text-muted)', border: '1px solid var(--border-color)',
                      padding: '0.2rem 0.5rem', borderRadius: '6px', fontWeight: 500 
                    }}>
                      Port {session.port || 22}
                    </span>

                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginLeft: 'auto', fontFamily: 'var(--font-mono)' }}>
                      ID: {session.id}
                    </span>

                  </div>

                  {/* Command Snippet Bar (if available) */}
                  {session.lastCommand && (
                    <div style={{
                      background: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '0.4rem 0.75rem',
                      fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#a7f3d0',
                      border: '1px solid rgba(255,255,255,0.04)', display: 'flex', alignItems: 'center', gap: '0.5rem',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                    }}>
                      <span style={{ color: 'var(--color-cyan)', fontWeight: 700 }}>&gt;</span>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{session.lastCommand}</span>
                    </div>
                  )}

                </div>
              );
            })
          )}
        </div>

      ) : (

        /* === GRAPH CLOUD VIEW (TOGGLE) === */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', height: 'calc(100vh - 200px)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="toggle-btn-group">
              {['type', 'duration', 'files'].map(gt => (
                <button 
                  key={gt}
                  className={`toggle-btn ${groupType === gt ? 'active' : ''}`}
                  onClick={() => setGroupType(gt)}
                >
                  Group by {gt.charAt(0).toUpperCase() + gt.slice(1)}
                </button>
              ))}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Showing {filteredSessions.length} interactive nodes • Click any node to inspect session
            </div>
          </div>

          <div className="viz-panel" style={{ flex: 1, position: 'relative' }}>
            <canvas 
              ref={canvasRef} 
              onMouseMove={handleCanvasMouseMove}
              onClick={handleCanvasClick}
            />
            
            {tooltip && (
              <div 
                className="viz-tooltip"
                style={{ left: `${tooltip.x}px`, top: `${tooltip.y}px` }}
              >
                <div className="viz-tooltip-title">{tooltip.session.ip}</div>
                <div className="viz-tooltip-row">
                  <span className="viz-tooltip-lbl">Country:</span>
                  <span className="viz-tooltip-val">{tooltip.session.country} ({tooltip.session.countryCode})</span>
                </div>
                <div className="viz-tooltip-row">
                  <span className="viz-tooltip-lbl">Threat Level:</span>
                  <span className="viz-tooltip-val" style={{ textTransform: 'capitalize', color: 'var(--color-cyan)' }}>{tooltip.session.threatLevel}</span>
                </div>
                <div className="viz-tooltip-row">
                  <span className="viz-tooltip-lbl">Duration:</span>
                  <span className="viz-tooltip-val">{formatDuration(tooltip.session.duration)}</span>
                </div>
                <div className="viz-tooltip-row">
                  <span className="viz-tooltip-lbl">Commands:</span>
                  <span className="viz-tooltip-val">{tooltip.session.commandsCount || 0} executed</span>
                </div>
                {tooltip.session.payloadFile && (
                  <div className="viz-tooltip-row">
                    <span className="viz-tooltip-lbl">Payload:</span>
                    <span className="viz-tooltip-val" style={{ color: 'var(--color-pink)' }}>{tooltip.session.payloadFile}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

      )}

    </div>
  );
}
