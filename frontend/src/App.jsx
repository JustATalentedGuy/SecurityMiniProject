import { useRef } from "react";
import {
  Activity,
  ArrowUpRight,
  FlaskConical,
  Inbox,
  KeyRound,
  LayoutDashboard,
  LogOut,
  RefreshCw,
  Send,
  ShieldCheck,
} from "lucide-react";
import {
  BrowserRouter,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import { useWorkspace } from "./hooks/useWorkspace";
import { Alert, Busy } from "./components/ui";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import SendPage from "./pages/Send";
import InboxPage from "./pages/Inbox";
import TransferDetails from "./pages/TransferDetails";
import Security from "./pages/Security";
import AttackLab from "./pages/AttackLab";
import Identity from "./pages/Identity";

function Workspace({ auth, logout }) {
  const workspace = useWorkspace(auth);
  const selectedFiles = useRef({});
  const location = useLocation();
  const nav = [
    ["/", "Dashboard", LayoutDashboard],
    ["/send", "Send file", Send],
    ["/received", "Received files", Inbox],
    ["/security", "Security monitor", Activity],
    ["/lab", "Attack lab", FlaskConical],
    ["/identity", "Identity & keys", KeyRound],
  ];
  const props = { auth, workspace, selectedFiles };
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <span className="brand-icon">
            <ShieldCheck size={22} />
          </span>
          SecureShare<span className="brand-x">X</span>
        </NavLink>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {nav.map(([path, label, Icon]) => (
            <NavLink key={path} end={path === "/"} to={path}>
              <Icon size={19} />
              <span>{label}</span>
              {path === "/lab" && <span className="nav-demo">DEMO</span>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-note">
          <ShieldCheck size={23} />
          <strong>Security you can explain.</strong>
          <p>
            Every identity, key exchange, and transfer leaves a verifiable
            trail.
          </p>
          <a href="/docs" target="_blank" rel="noreferrer">
            Explore API docs <ArrowUpRight size={15} />
          </a>
        </div>
        <div className="sidebar-user">
          <span className="avatar">
            {auth.user.username.slice(0, 1).toUpperCase()}
          </span>
          <div>
            <strong>{auth.user.username}</strong>
            <small>Local identity unlocked</small>
          </div>
          <button
            onClick={logout}
            aria-label="Lock & sign out"
            title="Lock & sign out"
          >
            <LogOut size={17} />
          </button>
        </div>
      </aside>
      <div className="workspace-body">
        <header className="topbar">
          <span>
            Workspace{" "}
            <span className="breadcrumb">
              /{" "}
              {nav.find(([path]) => path === location.pathname)?.[1] ||
                "Transfer details"}
            </span>
          </span>
          <div>
            <span className="connection">
              <span />
              Client-side encryption
            </span>
            <button
              className="icon-button"
              onClick={workspace.refresh}
              aria-label="Refresh workspace"
            >
              <RefreshCw size={17} />
            </button>
            <span className="avatar mini">
              {auth.user.username.slice(0, 1).toUpperCase()}
            </span>
          </div>
        </header>
        <main>
          <Alert error={workspace.error} />
          {workspace.loading ? (
            <Busy text="Loading your secure workspace…" />
          ) : (
            <Routes>
              <Route path="/" element={<Dashboard {...props} />} />
              <Route path="/send" element={<SendPage {...props} />} />
              <Route path="/received" element={<InboxPage {...props} />} />
              <Route
                path="/transfers/:id"
                element={<TransferDetails {...props} />}
              />
              <Route path="/security" element={<Security {...props} />} />
              <Route path="/lab" element={<AttackLab {...props} />} />
              <Route path="/identity" element={<Identity {...props} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          )}
          <footer className="workspace-footer">
            <span>SecureShare-X · Cryptography & Network Security</span>
            <span>RSA-PSS / X25519 / HKDF / AES-GCM</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
export default function App() {
  const { auth, logout } = useAuth();
  return (
    <BrowserRouter>
      {auth ? <Workspace auth={auth} logout={logout} /> : <Auth />}
    </BrowserRouter>
  );
}
