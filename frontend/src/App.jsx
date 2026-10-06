import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth';
import AccessLog from './pages/AccessLog';
import Audit from './pages/Audit';
import Dashboard from './pages/Dashboard';
import Devices from './pages/Devices';
import Login from './pages/Login';
import Policies from './pages/Policies';
import Simulator from './pages/Simulator';

const NAV = [
  { to: '/', label: 'Overview', end: true },
  { to: '/access', label: 'Access log' },
  { to: '/policies', label: 'Policies' },
  { to: '/simulator', label: 'Simulator' },
  { to: '/devices', label: 'Devices' },
  { to: '/audit', label: 'Audit trail', adminOnly: true },
];

function RequireAuth({ children }) {
  const { user } = useAuth();
  const location = useLocation();
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />;
  return children;
}

function Shell({ children }) {
  const { user, trust, logout, can } = useAuth();
  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          Zero Trust
          <span>Access gateway</span>
        </div>
        {NAV.filter((item) => !item.adminOnly || can('ADMIN')).map((item) => (
          <NavLink key={item.to} to={item.to} end={item.end}
                   className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            {item.label}
          </NavLink>
        ))}
        <div className="sidebar-footer">
          <div>{user.username} · {user.role}</div>
          <div className="subtle">Session trust score {trust}</div>
          <button style={{ marginTop: 8 }} onClick={logout}>Sign out</button>
        </div>
      </nav>
      <main className="main">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <RequireAuth>
              <Shell>
                <Routes>
                  <Route index element={<Dashboard />} />
                  <Route path="access" element={<AccessLog />} />
                  <Route path="policies" element={<Policies />} />
                  <Route path="simulator" element={<Simulator />} />
                  <Route path="devices" element={<Devices />} />
                  <Route path="audit" element={<Audit />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Shell>
            </RequireAuth>
          }
        />
      </Routes>
    </AuthProvider>
  );
}
