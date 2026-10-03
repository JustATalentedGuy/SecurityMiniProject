import {
  Fingerprint,
  RefreshCcw,
  Repeat2,
  ShieldAlert,
  ShieldX,
  Siren,
  Timer,
} from "lucide-react";
import { Badge, Empty, PageTitle, formatDate } from "../components/ui";

export default function Security({ workspace }) {
  const counts = workspace.stats.by_type;
  const metrics = [
    ["Failed logins", counts.LOGIN_FAILED || 0, ShieldX],
    ["Replay attacks", counts.REPLAY_ATTACK || 0, Repeat2],
    ["Tampering", counts.FILE_TAMPERING_DETECTED || 0, Fingerprint],
    ["Invalid signatures", counts.SIGNATURE_INVALID || 0, ShieldAlert],
    ["MITM detected", counts.MITM_DETECTED || 0, Siren],
    ["Rate violations", counts.RATE_LIMIT_EXCEEDED || 0, Timer],
  ];
  return (
    <>
      <PageTitle
        eyebrow="SECURITY MONITORING"
        title="Every signal, in view."
        description="Rule-based detection across your identity and transfers. Events update automatically."
        action={
          <button className="secondary" onClick={workspace.refresh}>
            <RefreshCcw size={16} />
            Refresh events
          </button>
        }
      />
      <div className="metrics security-metrics">
        {metrics.map(([label, count, Icon]) => (
          <div className="metric compact" key={label}>
            <span className="metric-icon blue">
              <Icon size={20} />
            </span>
            <strong>{count}</strong>
            <span className="muted">{label}</span>
          </div>
        ))}
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Security events{" "}
            <span className="count">{workspace.stats.total}</span>
          </h2>
          <span className="muted">Visible only to affected participants</span>
        </div>
        {workspace.events.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Severity</th>
                  <th>What happened</th>
                  <th>Time</th>
                  <th>Request ID</th>
                </tr>
              </thead>
              <tbody>
                {workspace.events.map((event) => (
                  <tr key={event.id}>
                    <td className="event-name">
                      {event.event_type.replaceAll("_", " ")}
                    </td>
                    <td>
                      <Badge value={event.severity} />
                    </td>
                    <td className="event-description">{event.description}</td>
                    <td className="muted">{formatDate(event.created_at)}</td>
                    <td>
                      <code title={event.request_id}>
                        {event.request_id.slice(0, 8)}
                      </code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No security events" />
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>Audit log</h2>
          <span className="muted">Append-only through the API</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>Resource</th>
                <th>Request ID</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {workspace.audit.map((entry) => (
                <tr key={entry.id}>
                  <td>{entry.action.replaceAll("_", " ")}</td>
                  <td>{entry.resource_type}</td>
                  <td>
                    <code>{entry.request_id}</code>
                  </td>
                  <td className="muted">{formatDate(entry.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
