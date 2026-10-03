import { useState } from "react";
import {
  ArrowRight,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  ShieldCheck,
} from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { Alert, Busy } from "../components/ui";

export default function Auth() {
  const { authenticate } = useAuth();
  const [mode, setMode] = useState("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [imported, setImported] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await authenticate({ username, password, mode, imported });
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }
  async function importFile(event) {
    try {
      const file = event.target.files[0];
      if (!file || file.size > 4 * 1024 * 1024)
        throw new Error(
          "Choose an encrypted vault JSON file smaller than 4 MB.",
        );
      const envelope = JSON.parse(await file.text());
      setImported(envelope);
      setUsername(envelope.username || "");
      setError(null);
    } catch (failure) {
      setError(failure);
    }
  }
  return (
    <div className="auth-layout">
      <section className="auth-story">
        <div className="brand">
          <span className="brand-icon">
            <ShieldCheck />
          </span>
          SecureShare<span className="brand-x">X</span>
        </div>
        <div className="story-body">
          <span className="eyebrow">TRUST, VERIFIED.</span>
          <h1>
            Private files.
            <br />
            Proven identities.
          </h1>
          <p>
            A secure exchange from the first handshake to the final fingerprint.
            See the cryptography. Understand the protection.
          </p>
          <div className="story-protocol">
            <div>
              <Fingerprint />
              <span>
                RSA-PSS<strong>Authenticated identities</strong>
              </span>
            </div>
            <div>
              <KeyRound />
              <span>
                X25519 + HKDF<strong>Fresh keys for every exchange</strong>
              </span>
            </div>
            <div>
              <LockKeyhole />
              <span>
                AES-256-GCM<strong>Encryption with integrity</strong>
              </span>
            </div>
          </div>
        </div>
        <footer>
          CRYPTOGRAPHY & NETWORK SECURITY LAB <span>PROTOCOL v1.0</span>
        </footer>
      </section>
      <section className="auth-form">
        <div className="auth-card">
          <span className="label">YOUR SECURE WORKSPACE</span>
          <h2>
            {mode === "register" ? "Create your identity" : "Welcome back"}
          </h2>
          <p>
            {mode === "register"
              ? "Your RSA identity is generated locally in this browser."
              : "Unlock your local identity to continue."}
          </p>
          <div className="auth-tabs">
            <button
              className={mode !== "register" ? "active" : ""}
              onClick={() => {
                setMode("password");
                setError(null);
              }}
            >
              Sign in
            </button>
            <button
              className={mode === "register" ? "active" : ""}
              onClick={() => {
                setMode("register");
                setError(null);
              }}
            >
              Register
            </button>
          </div>
          <form onSubmit={submit}>
            <label>
              Username
              <input
                required
                pattern="[a-zA-Z][a-zA-Z0-9_-]{2,31}"
                maxLength={32}
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                placeholder="e.g. alice"
              />
            </label>
            <label>
              {mode === "challenge" ? "Local vault password" : "Password"}
              <input
                required
                type="password"
                minLength={mode === "register" ? 10 : 1}
                maxLength={128}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete={
                  mode === "register" ? "new-password" : "current-password"
                }
                placeholder="Enter your password"
              />
            </label>
            {mode !== "register" && (
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={mode === "challenge"}
                  onChange={(event) =>
                    setMode(event.target.checked ? "challenge" : "password")
                  }
                />
                Use RSA challenge-response authentication
              </label>
            )}
            <label className="vault-import">
              Import encrypted key vault <span>(optional on this device)</span>
              <input
                type="file"
                accept=".json,application/json"
                onChange={importFile}
              />
            </label>
            {imported && (
              <p className="green">
                Encrypted vault selected for {imported.username}.
              </p>
            )}
            <Alert error={error} />
            <button className="primary full" disabled={busy}>
              {busy ? (
                <Busy
                  text={
                    mode === "register"
                      ? "Generating local RSA identity…"
                      : "Unlocking identity…"
                  }
                />
              ) : (
                <>
                  {mode === "register"
                    ? "Generate keys & register"
                    : mode === "challenge"
                      ? "Sign challenge & enter"
                      : "Sign in securely"}
                  <ArrowRight size={17} />
                </>
              )}
            </button>
          </form>
          <div className="key-warning">
            <ShieldCheck size={18} />
            <p>
              <strong>Never upload your private key to the server.</strong> Your
              encrypted key vault is opened locally. Back it up after key
              exchanges; losing it can make your files unrecoverable.
            </p>
          </div>
          <small className="muted">
            Use a recent Chrome, Edge, or Firefox with X25519 Web Crypto
            support. HTTPS or localhost is required.
          </small>
        </div>
      </section>
    </div>
  );
}
