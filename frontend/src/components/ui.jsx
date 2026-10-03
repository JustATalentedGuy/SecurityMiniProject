import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  FileLock2,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";

export const formatBytes = (value) =>
  value < 1024
    ? `${value} B`
    : value < 1048576
      ? `${(value / 1024).toFixed(1)} KB`
      : `${(value / 1048576).toFixed(1)} MB`;
export const formatDate = (value) =>
  new Date(value * 1000).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
const failures = [
  "TAMPERED",
  "SIGNATURE_INVALID",
  "REPLAY_REJECTED",
  "FAILED",
  "REJECTED",
  "HIGH",
  "CRITICAL",
];
export function Badge({ value }) {
  return (
    <span
      className={`badge ${failures.includes(value) ? "danger" : ["COMPLETED", "VERIFIED", "INFO", "ESTABLISHED"].includes(value) ? "success" : "pending"}`}
    >
      <span />
      {value.replaceAll("_", " ")}
    </span>
  );
}
export function Alert({ error, success, children }) {
  if (!error && !success && !children) return null;
  return (
    <div
      className={`alert ${error ? "error" : "good"}`}
      role={error ? "alert" : "status"}
    >
      {error ? <AlertTriangle size={19} /> : <CheckCircle2 size={19} />}
      <div>
        {error?.message || success || children}
        {error?.code && <small>{error.code}</small>}
        {error?.requestId && <small>Request ID: {error.requestId}</small>}
      </div>
    </div>
  );
}
export function PageTitle({ eyebrow, title, description, action }) {
  return (
    <div className="page-title">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
export function Empty({
  title = "No transfers yet",
  description = "Your encrypted exchanges will appear here.",
}) {
  return (
    <div className="empty">
      <FileLock2 size={34} />
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}
export function Busy({ text = "Working securely…" }) {
  return (
    <span className="busy">
      <LoaderCircle className="spin" size={17} />
      {text}
    </span>
  );
}

export function TransferTable({ transfers, received = false }) {
  if (!transfers.length) return <Empty />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>{received ? "Sender" : "Receiver"}</th>
            <th>Created</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {transfers.map((transfer) => (
            <tr key={transfer.id}>
              <td>
                <Link className="file-name" to={`/transfers/${transfer.id}`}>
                  <span className="file-icon">
                    <FileLock2 size={19} />
                  </span>
                  <span>
                    {transfer.safe_filename}
                    <small>{formatBytes(transfer.file_size)}</small>
                  </span>
                </Link>
              </td>
              <td>
                <span className="avatar mini">
                  {(received ? transfer.sender : transfer.receiver)
                    .slice(0, 1)
                    .toUpperCase()}
                </span>
                {received ? transfer.sender : transfer.receiver}
              </td>
              <td className="muted">{formatDate(transfer.created_at)}</td>
              <td>
                <Badge value={transfer.status} />
              </td>
              <td>
                <Link className="text-link" to={`/transfers/${transfer.id}`}>
                  View →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Pipeline({ transfer }) {
  const history = new Set(transfer?.history.map((item) => item.status));
  const failed = failures.includes(transfer?.status);
  const steps = [
    ["Identity & authentication", "RSA identity and bearer session", "CREATED"],
    [
      "Authenticated key exchange",
      "Ephemeral X25519 · RSA-PSS signatures",
      "KEY_ESTABLISHED",
    ],
    ["Session key derivation", "HKDF-SHA256 · transcript binding", "ENCRYPTED"],
    ["Encryption & fingerprint", "AES-256-GCM · SHA-256", "ENCRYPTED"],
    [
      "Digital signature & upload",
      "Signed context · ciphertext only",
      "AVAILABLE",
    ],
    [
      "Receiver verification",
      "Signature · GCM tag · file fingerprint",
      "VERIFIED",
    ],
    ["Verified receipt", "Receiver-signed completion record", "COMPLETED"],
  ];
  return (
    <ol className="pipeline">
      {steps.map(([title, subtitle, status]) => (
        <li
          key={title}
          className={history.has(status) ? "done" : failed ? "failed" : ""}
        >
          <span className="pipeline-dot">
            {history.has(status) ? (
              <CheckCircle2 size={18} />
            ) : failed ? (
              <AlertTriangle size={18} />
            ) : (
              <Clock3 size={18} />
            )}
          </span>
          <div>
            <strong>{title}</strong>
            <small>{subtitle}</small>
          </div>
          {history.has(status) && <ShieldCheck size={17} className="green" />}
        </li>
      ))}
    </ol>
  );
}
