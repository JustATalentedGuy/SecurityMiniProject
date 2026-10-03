import { PageTitle, TransferTable } from "../components/ui";

export default function Inbox({ workspace }) {
  return (
    <>
      <PageTitle
        eyebrow="YOUR INBOX"
        title="Received files"
        description="Accept signed key exchanges, then verify and decrypt files locally."
      />
      <div className="notice">
        Open a pending transfer to accept its key exchange. Once the sender
        uploads, use Verify & download to check every cryptographic layer.
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Incoming exchanges</h2>
          <span className="muted">{workspace.received.length} total</span>
        </div>
        <TransferTable transfers={workspace.received} received />
      </section>
    </>
  );
}
