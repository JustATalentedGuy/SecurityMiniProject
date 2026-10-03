import { useState } from "react";
import {
  FlaskConical,
  LockKeyhole,
  Network,
  Repeat2,
  ShieldX,
  Siren,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Alert, Busy, PageTitle } from "../components/ui";
import { api } from "../services/api";

export default function AttackLab({ auth, workspace }) {
  const [selected, setSelected] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(null);
  async function run(path, label) {
    setBusy(label);
    setError(null);
    setResult(null);
    try {
      setResult(
        await api(`/demo/${path}`, { method: "POST", token: auth.token }),
      );
    } catch (failure) {
      if (failure.code === "REPLAY_ATTACK_DETECTED")
        setResult({
          attack: "Replay request",
          rejected: true,
          explanation: failure.message,
          request_id: failure.requestId,
        });
      else setError(failure);
    } finally {
      await workspace.refresh();
      setBusy(null);
    }
  }
  if (!workspace.config.attack_demos_enabled)
    return (
      <>
        <PageTitle
          eyebrow="ATTACK LAB"
          title="Demonstrations disabled"
          description="Attack endpoints are removed when ENABLE_ATTACK_DEMOS=false."
        />
      </>
    );
  const transfers = [...workspace.sent, ...workspace.received];
  const labs = [
    {
      title: "Ciphertext tampering",
      icon: LockKeyhole,
      detail:
        "Change one byte of an encrypted object. The receiver rejects its fingerprint or GCM authentication tag.",
      label: "Tamper File",
      action: `transfers/${selected}/tamper`,
      needsTransfer: true,
    },
    {
      title: "Signature forgery",
      icon: ShieldX,
      detail:
        "Modify the sender signature. RSA-PSS verification rejects the transfer.",
      label: "Modify Signature",
      action: `transfers/${selected}/signature`,
      needsTransfer: true,
    },
    {
      title: "Request replay",
      icon: Repeat2,
      detail:
        "Reuse a consumed request nonce. The replay guard rejects it without reprocessing the transfer.",
      label: "Replay Request",
      action: `transfers/${selected}/replay`,
      needsTransfer: true,
    },
    {
      title: "Credential guessing",
      icon: Siren,
      detail:
        "Run invalid logins against your own demo identity. Failure counters trigger HTTP 429 and a temporary cooldown.",
      label: "Run Failed Login Simulation",
      action: "brute-force",
    },
  ];
  return (
    <>
      <PageTitle
        eyebrow="ISOLATED SECURITY LAB"
        title="Put the defenses to the test."
        description="Controlled attacks inside SecureShare-X, with visible evidence from real cryptographic checks."
        action={
          <Link className="secondary" to="/send">
            Normal Secure Transfer →
          </Link>
        }
      />
      <div className="lab-banner">
        <FlaskConical size={23} />
        <div>
          <strong>DEMO ATTACK MODE</strong>
          <p>
            Tamper controls alter disposable transfers you participate in. Use a
            fresh transfer for each tampering demo.
          </p>
        </div>
      </div>
      <section className="mitm-panel">
        <div>
          <span className="label">THE AUTHENTICATION DIFFERENCE</span>
          <h2>Same exchange. Different trust.</h2>
          <p>
            Plain DH lets Eve decrypt and relay a message through two separate
            shared secrets. Signed DH exposes the substituted public value.
          </p>
        </div>
        <div className="mitm-comparison">
          <div className="mitm-half insecure">
            <span className="chip">INSECURE DEMO MODE</span>
            <h3>Plain Diffie-Hellman</h3>
            <div className="network-flow">
              <span>Alice</span>
              <Network size={22} />
              <span className="eve">Eve</span>
              <Network size={22} />
              <span>Bob</span>
            </div>
            <p>
              No identity proof. Eve reads and re-encrypts the demo message.
            </p>
            <button
              className="danger-button"
              disabled={!!busy}
              onClick={() => run("mitm/plain", "Plain DH")}
            >
              {busy === "Plain DH" ? <Busy /> : "Simulate MITM on Plain DH"}
            </button>
          </div>
          <div className="mitm-half secure">
            <span className="chip">AUTHENTICATED DH</span>
            <h3>X25519 + RSA-PSS</h3>
            <div className="network-flow">
              <span>Alice</span>
              <LockKeyhole size={22} />
              <span className="blocked">Eve ✕</span>
              <LockKeyhole size={22} />
              <span>Bob</span>
            </div>
            <p>Signed public values. Substitution fails RSA verification.</p>
            <button
              className="primary"
              disabled={!!busy}
              onClick={() => run("mitm/authenticated", "Authenticated DH")}
            >
              {busy === "Authenticated DH" ? (
                <Busy />
              ) : (
                "Simulate MITM on Authenticated DH"
              )}
            </button>
          </div>
        </div>
      </section>
      <section className="panel form-panel lab-selector">
        <label>
          Disposable transfer for file attacks
          <select
            aria-label="Disposable transfer for file attacks"
            value={selected}
            onChange={(event) => setSelected(event.target.value)}
          >
            <option value="">Select one of your transfers</option>
            {transfers.map((transfer) => (
              <option key={transfer.id} value={transfer.id}>
                {transfer.safe_filename} · {transfer.status} ·{" "}
                {transfer.id.slice(0, 8)}
              </option>
            ))}
          </select>
        </label>
        {selected && (
          <Link className="text-link" to={`/transfers/${selected}`}>
            Open selected transfer →
          </Link>
        )}
      </section>
      <div className="lab-grid">
        {labs.map((lab) => (
          <section className="panel lab-card" key={lab.title}>
            <lab.icon size={24} />
            <h3>{lab.title}</h3>
            <p>{lab.detail}</p>
            <button
              className="secondary"
              disabled={!!busy || (lab.needsTransfer && !selected)}
              onClick={() => run(lab.action, lab.label)}
            >
              {busy === lab.label ? <Busy /> : lab.label}
            </button>
          </section>
        ))}
      </div>
      <Alert error={error} />
      {result && (
        <section className="panel lab-result" aria-live="polite">
          <div className="panel-heading">
            <h2>Demonstration result</h2>
            <span className="chip">
              {result.attacker_succeeded
                ? "ATTACK SUCCEEDED"
                : result.rejected ||
                    result.signature_valid === false ||
                    result.throttled
                  ? "DEFENSE RESPONDED"
                  : "ATTACK STAGED"}
            </span>
          </div>
          <p>{result.explanation || result.message}</p>
          {result.mechanism && (
            <p>
              <strong>Mechanism:</strong> {result.mechanism}
            </p>
          )}
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </section>
      )}
      <button
        className="text-button"
        disabled={!!busy}
        onClick={() => run("reset-cooldown", "Reset cooldown")}
      >
        Reset my demo login cooldown
      </button>
    </>
  );
}
