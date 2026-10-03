import { useState } from "react";
import { Download, FileLock2, Handshake, UploadCloud } from "lucide-react";
import { useParams } from "react-router-dom";
import {
  Alert,
  Badge,
  Busy,
  PageTitle,
  Pipeline,
  formatBytes,
  formatDate,
} from "../components/ui";
import {
  downloadBytes,
  receiveTransfer,
  respondToSession,
  uploadTransfer,
} from "../services/transfer";

export default function TransferDetails({ auth, workspace, selectedFiles }) {
  const { id } = useParams();
  const transfer = [...workspace.sent, ...workspace.received].find(
    (item) => item.id === id,
  );
  const [selected, setSelected] = useState(selectedFiles.current[id] || null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  async function action(kind) {
    setBusy(true);
    setError(null);
    setSuccess(null);
    try {
      if (kind === "respond") {
        setProgress("Verifying sender and signing your DH response");
        await respondToSession(auth, transfer.session);
        setSuccess(
          "Signed response sent. The sender can now encrypt and upload.",
        );
      }
      if (kind === "upload") {
        await uploadTransfer(auth, transfer, selected, setProgress);
        setSuccess(
          "Ciphertext uploaded. The receiver can now verify and decrypt.",
        );
      }
      if (kind === "receive") {
        const result = await receiveTransfer(
          auth,
          transfer,
          setProgress,
          workspace.config.replay_window_seconds,
        );
        downloadBytes(result.plaintext, result.filename, result.mimeType);
        result.plaintext.fill(0);
        setSuccess(
          "All checks passed. The decrypted file was downloaded locally.",
        );
      }
    } catch (failure) {
      setError(failure);
    } finally {
      await workspace.refresh();
      setBusy(false);
    }
  }
  if (!transfer)
    return (
      <Alert
        error={
          new Error(
            workspace.loading
              ? "Loading transfer…"
              : "Transfer not found in your workspace.",
          )
        }
      />
    );
  const sender = auth.user.id === transfer.sender_id;
  const canUpload =
    sender &&
    (transfer.session?.status === "RESPONDED" ||
      transfer.status === "KEY_ESTABLISHED");
  return (
    <>
      <PageTitle
        eyebrow="TRANSFER DETAILS"
        title={transfer.safe_filename}
        description={`${transfer.sender} → ${transfer.receiver} · ${formatBytes(transfer.file_size)} · ${formatDate(transfer.created_at)}`}
        action={<Badge value={transfer.status} />}
      />
      <Alert error={error} />
      <Alert success={success} />
      <div className="detail-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Cryptographic lifecycle</h2>
            <FileLock2 size={19} />
          </div>
          <Pipeline transfer={transfer} />
          <div className="subtle-note">
            Completion records a signed receiver receipt. Decryption and
            plaintext verification happen on the receiver's device.
          </div>
        </section>
        <div>
          <section className="panel form-panel">
            <h2>{sender ? "Sender actions" : "Receiver actions"}</h2>
            {!sender && transfer.session?.status === "PENDING" && (
              <>
                <p>
                  Verify the sender's signature and add your signed ephemeral
                  key to this exchange.
                </p>
                <button
                  className="primary full"
                  disabled={busy}
                  onClick={() => action("respond")}
                >
                  {busy ? (
                    <Busy text={progress} />
                  ) : (
                    <>
                      <Handshake size={18} />
                      Accept key exchange
                    </>
                  )}
                </button>
              </>
            )}
            {canUpload && (
              <>
                <label>
                  Original file
                  <input
                    type="file"
                    onChange={(event) => setSelected(event.target.files[0])}
                    aria-label="Original file"
                  />
                </label>
                {selected && <p className="muted">Selected: {selected.name}</p>}
                <button
                  className="primary full"
                  disabled={busy || !selected}
                  onClick={() => action("upload")}
                >
                  {busy ? (
                    <Busy text={progress} />
                  ) : (
                    <>
                      <UploadCloud size={18} />
                      Encrypt & upload
                    </>
                  )}
                </button>
              </>
            )}
            {!sender &&
              ["AVAILABLE", "DOWNLOADED", "COMPLETED"].includes(
                transfer.status,
              ) && (
                <>
                  <p>
                    Check both key exchange signatures, verify the file
                    signature, decrypt, and compare the plaintext fingerprint.
                  </p>
                  <button
                    className="primary full"
                    disabled={busy}
                    onClick={() => action("receive")}
                  >
                    {busy ? (
                      <Busy text={progress} />
                    ) : (
                      <>
                        <Download size={18} />
                        {transfer.status === "COMPLETED"
                          ? "Verify & download again"
                          : "Verify & download"}
                      </>
                    )}
                  </button>
                </>
              )}
            {sender && transfer.session?.status === "PENDING" && (
              <p className="notice">
                Waiting for {transfer.receiver} to accept the key exchange in
                their inbox.
              </p>
            )}
            {sender &&
              ["AVAILABLE", "DOWNLOADED"].includes(transfer.status) && (
                <p className="notice">
                  Waiting for the receiver's signed verification receipt.
                </p>
              )}
            {["TAMPERED", "SIGNATURE_INVALID", "FAILED", "REJECTED"].includes(
              transfer.status,
            ) && (
              <p className="notice danger-text">
                This transfer was rejected. Create a new exchange to try again.
              </p>
            )}
            {transfer.status === "COMPLETED" && (
              <p className="green">
                Receiver-signed receipt recorded successfully.
              </p>
            )}
          </section>
          <section className="panel metadata-panel">
            <div className="panel-heading">
              <h2>Signed context</h2>
            </div>
            <dl>
              <dt>Transfer ID</dt>
              <dd>
                <code>{transfer.id}</code>
              </dd>
              <dt>Session identifier</dt>
              <dd>
                <code>
                  {transfer.session?.session_identifier || "Not initiated"}
                </code>
              </dd>
              <dt>Session expiry</dt>
              <dd>
                {transfer.session
                  ? formatDate(transfer.session.expires_at)
                  : "—"}
              </dd>
              <dt>Plaintext SHA-256</dt>
              <dd>
                <code>
                  {transfer.metadata?.plaintext_sha256 ||
                    "Computed before encryption"}
                </code>
              </dd>
              <dt>Ciphertext SHA-256</dt>
              <dd>
                <code>
                  {transfer.metadata?.ciphertext_sha256 ||
                    "Available after upload"}
                </code>
              </dd>
              <dt>Transcript SHA-256</dt>
              <dd>
                <code>
                  {transfer.metadata?.transcript_sha256 ||
                    "Available after key confirmation"}
                </code>
              </dd>
              <dt>GCM nonce</dt>
              <dd>
                <code>
                  {transfer.metadata?.nonce || "Fresh nonce per encryption"}
                </code>
              </dd>
            </dl>
          </section>
        </div>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Transfer history</h2>
        </div>
        <div className="history">
          {transfer.history.map((step, index) => (
            <div key={index}>
              <Badge value={step.status} />
              <span>{formatDate(step.timestamp)}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
