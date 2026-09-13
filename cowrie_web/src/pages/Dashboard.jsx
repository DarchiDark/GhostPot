import { useEffect, useRef, useState } from 'react';
import { ShieldAlert, Users, DownloadCloud, Terminal, TrendingUp, Radio, Globe, KeyRound, Loader2 } from 'lucide-react';
import { getStats, getLiveFeed } from '../data';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [feed, setFeed] = useState([]);
  const [liveStats, setLiveStats] = useState(null);
  const [loading, setLoading] = useState(true);

  const chartRef = useRef(null);
  const mapRef = useRef(null);
  const mapAnimRef = useRef(null);

  useEffect(() => {
    async function loadData() {
      try {
        const data = await getStats();
        setStats(data);
        setLiveStats({
          totalSessions: data.totalSessions,
          uniqueIPs: data.uniqueIPs,
          totalDownloads: data.totalDownloads,
          totalCommands: data.totalCommands,
        });
        const initialFeed = await getLiveFeed();
        setFeed(initialFeed);
      } catch (e) {
        console.error('Failed to load dashboard data:', e);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Live feed & stats polling
  useEffect(() => {
    if (!stats) return;
    const id = setInterval(async () => {
      try {
        const newFeed = await getLiveFeed();
        setFeed(newFeed);
        const newStats = await getStats();
        setStats(newStats);
        setLiveStats({
          totalSessions: newStats.totalSessions,
          uniqueIPs: newStats.uniqueIPs,
          totalDownloads: newStats.totalDownloads,
          totalCommands: newStats.totalCommands,
        });
      } catch (e) {
        console.error(e);
      }
    }, 3500);
    return () => clearInterval(id);
  }, [stats]);

  // Smooth spline Timeline chart
  useEffect(() => {
    if (!stats) return;
    const canvas = chartRef.current;
    if (!canvas) return;
    const draw = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.parentElement.getBoundingClientRect();
      const w = Math.floor(rect.width) || 600;
      const h = Math.floor(rect.height) || 260;
      canvas.width = w * dpr; canvas.height = h * dpr;
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);

      const data = stats.timelineData || [0];
      const maxV = Math.max(...data, 5);
      const pL = 40, pR = 20, pT = 25, pB = 35;
      const cW = w - pL - pR, cH = h - pT - pB;

      // Horizontal grid lines
      ctx.strokeStyle = 'rgba(255,255,255,0.04)'; ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = pT + (cH * i) / 4;
        ctx.beginPath(); ctx.moveTo(pL, y); ctx.lineTo(w - pR, y); ctx.stroke();
        ctx.fillStyle = '#6b7280'; ctx.font = '9px "JetBrains Mono",monospace'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
        ctx.fillText(Math.round(maxV - (maxV * i) / 4), pL - 8, y);
      }

      // Compute points
      const pts = data.map((v, i) => ({
        x: pL + (i * cW) / Math.max(1, data.length - 1),
        y: pT + cH - (v / maxV) * cH,
        val: v
      }));

      // Draw accurate Catmull-Rom smooth curve (passing exactly through every point)
      if (pts.length > 1) {
        // Gradient fill
        const grad = ctx.createLinearGradient(0, pT, 0, pT + cH);
        grad.addColorStop(0, 'rgba(0,245,212,0.25)');
        grad.addColorStop(0.7, 'rgba(0,245,212,0.04)');
        grad.addColorStop(1, 'rgba(0,245,212,0)');

        ctx.beginPath();
        ctx.moveTo(pts[0].x, pT + cH);
        ctx.lineTo(pts[0].x, pts[0].y);

        for (let i = 0; i < pts.length - 1; i++) {
          const p0 = pts[i === 0 ? 0 : i - 1];
          const p1 = pts[i];
          const p2 = pts[i + 1];
          const p3 = pts[i + 2 >= pts.length ? pts.length - 1 : i + 2];

          const cp1x = p1.x + (p2.x - p0.x) / 6;
          const cp1y = Math.min(pT + cH, Math.max(pT, p1.y + (p2.y - p0.y) / 6));
          const cp2x = p2.x - (p3.x - p1.x) / 6;
          const cp2y = Math.min(pT + cH, Math.max(pT, p2.y - (p3.y - p1.y) / 6));

          ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
        }

        ctx.lineTo(pts[pts.length - 1].x, pT + cH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();

        // Stroke glowing line (passes exactly through each point)
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(pts[0].x, pts[0].y);

        for (let i = 0; i < pts.length - 1; i++) {
          const p0 = pts[i === 0 ? 0 : i - 1];
          const p1 = pts[i];
          const p2 = pts[i + 1];
          const p3 = pts[i + 2 >= pts.length ? pts.length - 1 : i + 2];

          const cp1x = p1.x + (p2.x - p0.x) / 6;
          const cp1y = Math.min(pT + cH, Math.max(pT, p1.y + (p2.y - p0.y) / 6));
          const cp2x = p2.x - (p3.x - p1.x) / 6;
          const cp2y = Math.min(pT + cH, Math.max(pT, p2.y - (p3.y - p1.y) / 6));

          ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
        }

        ctx.strokeStyle = '#00f5d4';
        ctx.lineWidth = 2.5;
        ctx.shadowColor = '#00f5d4';
        ctx.shadowBlur = 8;
        ctx.stroke();
        ctx.restore();

        // Dots on points (now lying perfectly on the line)
        pts.forEach(p => {
          if (p.val > 0) {
            ctx.beginPath();
            ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.strokeStyle = '#00f5d4';
            ctx.lineWidth = 2;
            ctx.shadowColor = '#00f5d4';
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.stroke();
          }
        });
      }

      // Time axis labels
      ctx.fillStyle = '#6b7280'; ctx.font = '9px "Inter",sans-serif'; ctx.textAlign = 'center';
      [0, 6, 12, 18, 23].forEach(i => {
        if (pts[i]) {
          ctx.fillText(23 - i === 0 ? 'Now' : `${23 - i}h ago`, pts[i].x, pT + cH + 16);
        }
      });
    };
    draw();
    window.addEventListener('resize', draw);
    return () => window.removeEventListener('resize', draw);
  }, [stats]);

// Simplified Equirectangular Continents for Cyberpunk Neon World Map
const WORLD_CONTINENTS = [
  // North America
  [[-168, 65], [-160, 71], [-140, 70], [-125, 70], [-100, 70], [-80, 74], [-64, 62], [-60, 50], [-70, 42], [-75, 35], [-80, 25], [-97, 20], [-80, 8], [-77, 8], [-90, 15], [-105, 20], [-117, 32], [-125, 48], [-135, 58], [-168, 65]],
  // Greenland
  [[-44, 60], [-20, 70], [-18, 77], [-20, 82], [-60, 83], [-55, 70], [-44, 60]],
  // South America
  [[-77, 8], [-60, 10], [-50, -2], [-35, -5], [-35, -12], [-40, -22], [-55, -35], [-65, -55], [-75, -50], [-72, -35], [-81, -5], [-77, 8]],
  // Europe & Scandinavia
  [[-10, 36], [-8, 43], [0, 43], [10, 45], [15, 40], [20, 40], [25, 36], [35, 32], [30, 45], [20, 55], [15, 60], [25, 71], [30, 70], [40, 68], [30, 60], [10, 55], [5, 50], [-5, 50], [-10, 43], [-10, 36]],
  // United Kingdom & Ireland
  [[-5, 50], [2, 52], [0, 58], [-4, 58], [-6, 55], [-10, 52], [-5, 50]],
  // Africa
  [[-10, 36], [0, 36], [10, 37], [25, 32], [32, 31], [35, 25], [43, 12], [51, 10], [40, -15], [33, -28], [30, -31], [18, -34], [15, -25], [12, -15], [9, 4], [-15, 12], [-17, 15], [-10, 36]],
  // Madagascar
  [[44, -12], [50, -15], [47, -25], [43, -25], [44, -12]],
  // Asia & Siberia
  [[35, 32], [50, 26], [60, 25], [70, 20], [80, 10], [85, 20], [92, 10], [100, 3], [108, 12], [120, 22], [122, 30], [120, 40], [130, 42], [140, 50], [160, 55], [180, 65], [170, 70], [140, 72], [100, 77], [80, 75], [60, 70], [40, 68], [35, 55], [35, 32]],
  // Japan
  [[130, 32], [141, 38], [145, 44], [140, 45], [132, 34], [130, 32]],
  // Australia
  [[114, -22], [125, -15], [136, -12], [145, -15], [153, -28], [150, -37], [138, -35], [115, -34], [114, -22]],
  // New Zealand
  [[168, -46], [174, -41], [178, -38], [174, -36], [168, -46]],
  // Indonesia / SE Asia Islands
  [[98, 3], [105, -5], [115, -8], [125, -8], [128, 2], [120, 15], [105, 5], [98, 3]]
];

  // High-Tech Geographic Radar Map with Neon World Map
  useEffect(() => {
    if (!stats) return;
    const canvas = mapRef.current;
    if (!canvas) return;
    let running = true;

    const render = () => {
      if (!running) return;
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.parentElement.clientWidth || 500;
      const h = canvas.parentElement.clientHeight || 350;
      canvas.width = w * dpr; canvas.height = h * dpr;
      canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);

      const now = Date.now();

      // Coordinate converter (Equirectangular)
      const toX = (lng) => ((lng + 180) / 360) * w;
      const toY = (lat) => ((90 - lat) / 180) * h;

      // 1. Cyber Latitude/Longitude Grid
      ctx.strokeStyle = 'rgba(255,255,255,0.025)'; ctx.lineWidth = 1;
      for (let c = 0; c <= 12; c++) {
        const x = (w * c) / 12;
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let r = 0; r <= 8; r++) {
        const y = (h * r) / 8;
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // Equator & Prime Meridian Highlight
      ctx.strokeStyle = 'rgba(0,245,212,0.07)';
      ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(w / 2, 0); ctx.lineTo(w / 2, h); ctx.stroke();
      ctx.setLineDash([]);

      // 2. Neon World Continents
      ctx.save();
      WORLD_CONTINENTS.forEach(polygon => {
        if (polygon.length < 2) return;
        ctx.beginPath();
        const start = polygon[0];
        ctx.moveTo(toX(start[0]), toY(start[1]));
        for (let i = 1; i < polygon.length; i++) {
          ctx.lineTo(toX(polygon[i][0]), toY(polygon[i][1]));
        }
        ctx.closePath();

        // Neon fill
        ctx.fillStyle = 'rgba(0, 245, 212, 0.035)';
        ctx.fill();

        // Neon glowing stroke
        ctx.strokeStyle = 'rgba(0, 245, 212, 0.45)';
        ctx.lineWidth = 1.3;
        ctx.shadowColor = '#00f5d4';
        ctx.shadowBlur = 6;
        ctx.stroke();
      });
      ctx.restore();

      // 3. Concentric Radar Rings
      const cx0 = w / 2, cy0 = h / 2;
      ctx.strokeStyle = 'rgba(0,245,212,0.06)'; ctx.lineWidth = 1;
      [0.25, 0.5, 0.75, 0.95].forEach(ratio => {
        ctx.beginPath();
        ctx.arc(cx0, cy0, Math.min(w, h) * ratio * 0.5, 0, Math.PI * 2);
        ctx.stroke();
      });

      // 4. Rotating Radar Scanner Sweep
      const sweepAngle = (now * 0.0007) % (Math.PI * 2);
      ctx.save();
      const sweepGrad = ctx.createRadialGradient(cx0, cy0, 0, cx0, cy0, Math.max(w, h) * 0.65);
      sweepGrad.addColorStop(0, 'rgba(0,245,212,0.08)');
      sweepGrad.addColorStop(1, 'rgba(0,245,212,0)');
      ctx.beginPath();
      ctx.moveTo(cx0, cy0);
      ctx.arc(cx0, cy0, Math.max(w, h) * 0.65, sweepAngle - 0.45, sweepAngle);
      ctx.closePath();
      ctx.fillStyle = sweepGrad;
      ctx.fill();
      ctx.restore();

      // 5. Attacking Country Beacons
      (stats.countries || []).forEach((c, idx) => {
        const cx = toX(c.lng);
        const cy = toY(c.lat);
        const pulse = 6 + Math.sin(now * 0.003 - idx) * 4;

        ctx.save();
        // Expanding Ripple
        ctx.beginPath();
        ctx.arc(cx, cy, pulse * 2.4, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(247,37,133,${0.15 * (1 - pulse / 10)})`;
        ctx.strokeStyle = `rgba(247,37,133,${0.5 * (1 - pulse / 10)})`;
        ctx.lineWidth = 1.5;
        ctx.fill();
        ctx.stroke();

        // Neon Pink Target Beacon
        ctx.beginPath();
        ctx.arc(cx, cy, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = '#f72585';
        ctx.shadowColor = '#f72585';
        ctx.shadowBlur = 14;
        ctx.fill();
        ctx.restore();

        // Country Tag Badge
        if (idx < 6) {
          ctx.save();
          ctx.fillStyle = '#0c0f17';
          ctx.strokeStyle = 'rgba(247,37,133,0.4)';
          ctx.lineWidth = 1;
          const text = `${c.code} [${c.count}]`;
          ctx.font = 'bold 9px "JetBrains Mono",monospace';
          const textW = ctx.measureText(text).width;
          
          ctx.fillRect(cx + 8, cy - 8, textW + 6, 14);
          ctx.strokeRect(cx + 8, cy - 8, textW + 6, 14);

          ctx.fillStyle = '#f3f4f6';
          ctx.textAlign = 'left';
          ctx.textBaseline = 'middle';
          ctx.fillText(text, cx + 11, cy - 1);
          ctx.restore();
        }
      });

      mapAnimRef.current = requestAnimationFrame(render);
    };
    render();
    return () => { running = false; cancelAnimationFrame(mapAnimRef.current); };
  }, [stats]);

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', color: 'var(--text-muted)' }}>
        <Loader2 className="animate-spin" size={32} style={{ marginBottom: '1rem', color: 'var(--color-cyan)' }} />
        <p>Loading Dashboard Stats...</p>
      </div>
    );
  }

  return (
    <div className="page-enter">
      <div className="stats-grid">
        {[
          { label: 'Total Sessions', value: liveStats.totalSessions, Icon: ShieldAlert, color: 'var(--color-cyan)' },
          { label: 'Unique Attackers', value: liveStats.uniqueIPs, Icon: Users, color: 'var(--color-blue)' },
          { label: 'Payloads Dropped', value: liveStats.totalDownloads, Icon: DownloadCloud, color: 'var(--color-pink)' },
          { label: 'Commands Input', value: liveStats.totalCommands, Icon: Terminal, color: 'var(--color-amber)' },
        ].map(s => (
          <div className="card stat-card" key={s.label} style={{ '--accent-color': s.color }}>
            <div className="stat-info">
              <h3>{s.label}</h3>
              <div className="stat-value">{s.value}</div>
            </div>
            <div className="stat-icon"><s.Icon size={24} /></div>
          </div>
        ))}
      </div>

      <div className="dashboard-grid">
        <div className="card chart-card">
          <div className="card-title"><TrendingUp size={18} /> Threat Activity (Last 24 Hours)</div>
          <div className="chart-container"><canvas ref={chartRef} /></div>
        </div>
        <div className="card live-feed-card">
          <div className="card-title"><Radio size={18} style={{ color: 'var(--color-pink)' }} /> Live Honeypot Feed</div>
          <div className="live-feed-list">
            {feed.map((e, i) => (
              <div className="feed-item" key={i}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span className={`feed-badge ${e.badgeClass}`}>{e.type}</span>
                  <div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{e.detail}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.15rem' }}>
                      {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })} • {e.country}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="geo-grid">
        <div className="card">
          <div className="card-title"><Globe size={18} /> Geographic Attack Distribution</div>
          <div style={{ height: 350, position: 'relative' }}><canvas ref={mapRef} style={{ width: '100%', height: '100%', display: 'block' }} /></div>
        </div>
        <div className="card" style={{ maxHeight: 416, display: 'flex', flexDirection: 'column' }}>
          <div className="card-title"><KeyRound size={18} /> Top Bruteforced Credentials</div>
          <div className="table-wrapper" style={{ flex: 1, overflowY: 'auto' }}>
            <table>
              <thead><tr><th>Username</th><th>Password</th><th>Count</th></tr></thead>
              <tbody>
                {stats.topCredentials.map((c, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ color: 'var(--color-cyan)' }}>{c.username}</td>
                    <td className="mono" style={{ color: 'var(--text-secondary)' }}>{c.password || '<empty>'}</td>
                    <td className="mono" style={{ textAlign: 'right', color: 'var(--color-pink)', fontWeight: 'bold' }}>{c.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
