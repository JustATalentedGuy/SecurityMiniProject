import {
  ArrowUpRight,
  CheckCheck,
  FileInput,
  FileOutput,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  Badge,
  Empty,
  PageTitle,
  TransferTable,
  formatDate,
} from "../components/ui";

export default function Dashboard({ auth, workspace }) {
  const all = [...workspace.sent, ...workspace.received].sort(
    (a, b) => b.created_at - a.created_at,
  );
  const metrics = [
    ["Files sent", workspace.summary.sent, FileOutput, "blue"],
    ["Files received", workspace.summary.received, FileInput, "purple"],
    ["Completed transfers", workspace.summary.completed, CheckCheck, "green"],
    [
      "Security alerts",
      ["HIGH", "CRITICAL", "MEDIUM"].reduce(
        (sum, severity) => sum + (workspace.stats.by_severity[severity] || 0),
        0,
      ),
      ShieldAlert,
      "orange",
    ],
  ];
  return (
    <>
      <PageTitle
        eyebrow="WORKSPACE OVERVIEW"
        title={`Welcome back, ${auth.user.username}.`}
        description="Your exchanges, verified from identity to integrity."
        action={
          <Link className="primary" to="/send">
            Send a file <ArrowUpRight size={18} />
          </Link>
        }
      />
      <div className="metrics">
        {metrics.map(([label, count, Icon, color]) => (
          <div className="metric" key={label}>
            <span className={`metric-icon ${color}`}>
              <Icon size={22} />
            </span>
            <span className="muted">{label}</span>
            <strong>{count.toString().padStart(2, "0")}</strong>
            <small>
              {label === "Security alerts"
                ? "Real events from your exchanges"
                : "Across your secure workspace"}
            </small>
          </div>
        ))}
      </div>
      <div className="security-strip">
        <ShieldCheck size={25} />
        <div>
          <strong>Your private keys stay with you.</strong>
          <span>
            RSA-PSS identity · authenticated X25519 · AES-256-GCM · SHA-256
            integrity
          </span>
        </div>
        <span className="chip">CLIENT-SIDE CRYPTO</span>
      </div>
      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Recent exchanges</h2>
            <span className="muted">{workspace.summary.pending} pending</span>
          </div>
          <TransferTable transfers={all.slice(0, 6)} />
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Security activity</h2>
            <Link className="text-link" to="/security">
              View all →
            </Link>
          </div>
          {workspace.events.length ? (
            <div className="event-feed">
              {workspace.events.slice(0, 5).map((event) => (
                <div className="feed-item" key={event.id}>
                  <ShieldCheck size={18} />
                  <div>
                    <strong>{event.event_type.replaceAll("_", " ")}</strong>
                    <small>{formatDate(event.created_at)}</small>
                  </div>
                  <Badge value={event.severity} />
                </div>
              ))}
            </div>
          ) : (
            <Empty
              title="All quiet"
              description="Security events will appear as you use the workspace."
            />
          )}
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Recent audit trail</h2>
          <span className="muted">Every important action has a request ID</span>
        </div>
        <div className="audit-feed">
          {workspace.audit.slice(0, 5).map((item) => (
            <div key={item.id}>
              <span className="audit-dot" />
              <strong>{item.action.replaceAll("_", " ")}</strong>
              <code title={item.request_id}>{item.request_id.slice(0, 8)}</code>
              <span>{formatDate(item.created_at)}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
