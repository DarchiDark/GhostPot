import { Routes, Route, NavLink } from 'react-router-dom';
import { LayoutDashboard, Activity } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import Sessions from './pages/Sessions';
import SessionDetail from './pages/SessionDetail';

export default function App() {
  return (
    <Routes>
      {/* Session detail is a standalone full-screen page */}
      <Route path="/session/:id" element={<SessionDetail />} />
      <Route path="/sessions/:id" element={<SessionDetail />} />
      {/* Main layout with header */}
      <Route path="*" element={<MainLayout />} />
    </Routes>
  );
}

function MainLayout() {
  return (
    <div className="app-container">
      <header>
        <NavLink to="/" className="logo">
          <div className="logo-icon">&gt;_</div>
          <div className="logo-text">GHOSTPOT</div>
        </NavLink>
        <nav>
          <NavLink to="/" end className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
            <LayoutDashboard size={16}/> Dashboard
          </NavLink>
          <NavLink to="/sessions" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
            <Activity size={16}/> Sessions Cloud
          </NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/sessions" element={<Sessions />} />
        </Routes>
      </main>
    </div>
  );
}
