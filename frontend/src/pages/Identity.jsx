import { useState } from "react";
import { Download, KeyRound } from "lucide-react";
import { Alert, PageTitle } from "../components/ui";
import { downloadBytes } from "../services/transfer";

export default function Identity({ auth }) {
  const [message, setMessage] = useState(null);
  async function backup() {
    const envelope = await auth.persist();
    downloadBytes(
      JSON.stringify(envelope, null, 2),
      `${auth.user.username}.vault.json`,
      "application/json",
    );
    setMessage(
      "Encrypted backup downloaded. Keep it private and back it up again after new key exchanges.",
    );
  }
  return (
    <>
      <PageTitle
        eyebrow="LOCAL IDENTITY"
        title="Your keys. Your control."
        description="The server stores your RSA public key. Your encrypted private key vault stays on this device."
      />
      <Alert success={message} />
      <div className="detail-grid">
        <section className="panel form-panel">
          <KeyRound className="blue-text" size={30} />
          <h2>{auth.user.username}'s identity</h2>
          <dl>
            <dt>Public key fingerprint · SHA-256</dt>
            <dd>
              <code>{auth.user.fingerprint}</code>
            </dd>
            <dt>RSA signature scheme</dt>
            <dd>RSA-PSS · SHA-256 · 32-byte salt</dd>
            <dt>Vault encryption</dt>
            <dd>PBKDF2-SHA256 · 600,000 iterations · AES-256-GCM</dd>
            <dt>Local ephemeral keys</dt>
            <dd>{Object.keys(auth.vault.sessions).length} exchange records</dd>
            <dt>Pinned contact identities</dt>
            <dd>
              {Object.keys(auth.vault.pins).length} public key fingerprints
            </dd>
          </dl>
          <button className="primary" onClick={backup}>
            <Download size={17} />
            Download encrypted key vault
          </button>
        </section>
        <section className="panel form-panel">
          <h2>Backup & trust</h2>
          <p>
            Use the encrypted vault import on the login screen to use your
            identity on another device. The password unlocks the vault locally.
          </p>
          <p>
            Exchange contact fingerprints through a trusted channel. Keys are
            pinned on first use; a changed fingerprint blocks future
            cryptographic operations.
          </p>
          <p>
            Backups include exchange keys needed to decrypt existing files. Back
            up again after accepting a handshake. Losing those keys makes stored
            ciphertext unrecoverable.
          </p>
          <div className="notice">
            Never upload your private key to the server. A forgotten vault
            password cannot be reset into recovering encrypted content.
          </div>
        </section>
      </div>
      <section className="panel form-panel">
        <h2>Registered public key</h2>
        <pre className="public-key">{auth.user.public_key_pem}</pre>
      </section>
    </>
  );
}
