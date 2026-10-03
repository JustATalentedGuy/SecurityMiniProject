import { useState } from "react";
import {
  FileLock2,
  LockKeyhole,
  SendHorizonal,
  UploadCloud,
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  Alert,
  Busy,
  PageTitle,
  TransferTable,
  formatBytes,
} from "../components/ui";
import { initiateTransfer } from "../services/transfer";
import { sha256 } from "../utils/crypto";

export default function Send({ auth, workspace, selectedFiles }) {
  const [receiver, setReceiver] = useState("");
  const [file, setFile] = useState(null);
  const [fingerprint, setFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState(null);
  const [created, setCreated] = useState(null);
  async function chooseFile(event) {
    const selected = event.target.files[0];
    setFile(selected);
    setError(null);
    setCreated(null);
    if (!selected) return;
    if (selected.size > (workspace.config.max_upload_mb || 25) * 1048576) {
      setError(new Error("This file exceeds the configured upload limit."));
      setFile(null);
      return;
    }
    setFingerprint(await sha256(await selected.arrayBuffer()));
  }
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const transfer = await initiateTransfer(
        auth,
        file,
        receiver,
        setProgress,
      );
      selectedFiles.current[transfer.id] = file;
      setCreated(transfer);
      await workspace.refresh();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageTitle
        eyebrow="SECURE EXCHANGE"
        title="Send a file"
        description="Start an authenticated handshake. Encrypt after the receiver accepts."
      />
      <div className="send-grid">
        <section className="panel form-panel">
          <h2>New encrypted transfer</h2>
          <form onSubmit={submit}>
            <label>
              Recipient
              <select
                aria-label="Recipient"
                required
                value={receiver}
                onChange={(event) => setReceiver(event.target.value)}
              >
                <option value="">Select a registered user</option>
                {workspace.users
                  .filter((user) => user.id !== auth.user.id)
                  .map((user) => (
                    <option value={user.id} key={user.id}>
                      {user.username} · {user.fingerprint.slice(0, 12)}
                    </option>
                  ))}
              </select>
            </label>
            <label className="dropzone">
              <UploadCloud size={32} />
              <strong>{file ? file.name : "Choose a file to exchange"}</strong>
              <span>
                {file
                  ? formatBytes(file.size)
                  : `Up to ${workspace.config.max_upload_mb || 25} MB · encrypted in your browser`}
              </span>
              <input
                required
                type="file"
                onChange={chooseFile}
                aria-label="File to send"
              />
            </label>
            {fingerprint && file && (
              <div className="fingerprint-box">
                <span className="label">PLAINTEXT SHA-256</span>
                <code>{fingerprint}</code>
              </div>
            )}
            <Alert error={error} />
            <Alert
              success={
                created &&
                "Handshake initiated. The receiver must accept in Received Files, then you can encrypt and upload."
              }
            />
            {created ? (
              <Link className="primary full" to={`/transfers/${created.id}`}>
                Continue transfer →
              </Link>
            ) : (
              <button
                className="primary full"
                disabled={busy || !file || !receiver}
              >
                {busy ? (
                  <Busy text={progress} />
                ) : (
                  <>
                    Start authenticated exchange <SendHorizonal size={18} />
                  </>
                )}
              </button>
            )}
          </form>
        </section>
        <section className="panel protection-card">
          <span className="large-icon">
            <LockKeyhole size={32} />
          </span>
          <h2>Protection at every step</h2>
          <p>
            Your receiver participates in the key exchange. No file content is
            sent until the exchange is authenticated.
          </p>
          {[
            [
              "01",
              "Authenticate identities",
              "RSA-PSS signs both ephemeral public keys.",
            ],
            [
              "02",
              "Derive a fresh session key",
              "X25519 and HKDF bind the key to this exchange.",
            ],
            [
              "03",
              "Encrypt, sign, and send",
              "AES-GCM encrypts the file; RSA-PSS signs its metadata.",
            ],
            [
              "04",
              "Verify before accepting",
              "The receiver checks signatures, the GCM tag, and SHA-256.",
            ],
          ].map(([number, title, detail]) => (
            <div className="protection-step" key={number}>
              <span>{number}</span>
              <div>
                <strong>{title}</strong>
                <p>{detail}</p>
              </div>
            </div>
          ))}
          <div className="subtle-note">
            <FileLock2 size={18} />
            Only encrypted content reaches server storage.
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Sent files</h2>
          <span className="muted">Track pending handshakes and delivery</span>
        </div>
        <TransferTable transfers={workspace.sent} />
      </section>
    </>
  );
}
