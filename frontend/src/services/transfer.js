import { api } from "./api";
import {
  PROTOCOL,
  b64,
  bytes,
  canonical,
  decryptFile,
  deriveAES,
  encryptFile,
  generateEphemeral,
  nonce,
  sha256,
  sign,
  timestamp,
  transcriptHash,
  verify,
  pemBytes,
} from "../utils/crypto";

async function trustedKey(auth, userId) {
  const user = await api(`/users/${userId}/public-key`, { token: auth.token });
  const fingerprint = await sha256(pemBytes(user.public_key_pem));
  if (fingerprint !== user.fingerprint)
    throw new Error("Registry fingerprint does not match its public key.");
  if (auth.vault.pins[userId] && auth.vault.pins[userId] !== fingerprint)
    throw new Error(
      "Identity fingerprint changed. Verify the key with your contact before proceeding.",
    );
  auth.vault.pins[userId] = fingerprint;
  await auth.persist();
  return user.public_key_pem;
}

export async function verifySession(auth, session, { responded = true } = {}) {
  const senderKey = await trustedKey(auth, session.sender_id);
  if (
    !(await verify(
      senderKey,
      session.sender_signature,
      session.sender_metadata,
    ))
  )
    throw new Error("MITM detected: sender key exchange signature is invalid.");
  const sender = session.sender_metadata;
  if (
    sender.protocol !== PROTOCOL ||
    sender.purpose !== "dh-initiate" ||
    sender.transfer_id !== session.transfer_id ||
    sender.session_identifier !== session.session_identifier ||
    sender.sender_id !== session.sender_id ||
    sender.receiver_id !== session.receiver_id ||
    sender.receiver_ephemeral_public_key !== null
  )
    throw new Error("Sender key exchange context does not match.");
  if (responded) {
    const receiverKey = await trustedKey(auth, session.receiver_id);
    if (
      !session.receiver_metadata ||
      !(await verify(
        receiverKey,
        session.receiver_signature,
        session.receiver_metadata,
      ))
    )
      throw new Error(
        "MITM detected: receiver key exchange signature is invalid.",
      );
    const receiver = session.receiver_metadata;
    if (
      receiver.protocol !== PROTOCOL ||
      receiver.purpose !== "dh-respond" ||
      receiver.transfer_id !== sender.transfer_id ||
      receiver.session_identifier !== sender.session_identifier ||
      receiver.sender_id !== sender.sender_id ||
      receiver.receiver_id !== sender.receiver_id ||
      receiver.sender_ephemeral_public_key !==
        sender.sender_ephemeral_public_key ||
      !receiver.receiver_ephemeral_public_key
    )
      throw new Error("Receiver key exchange context does not match.");
  }
  return senderKey;
}

export async function initiateTransfer(auth, file, receiverId, progress) {
  progress("Creating transfer record");
  const transfer = await api("/transfers", {
    method: "POST",
    token: auth.token,
    headers: { "Idempotency-Key": crypto.randomUUID() },
    data: {
      receiver_id: receiverId,
      original_filename: file.name,
      mime_type: file.type || "application/octet-stream",
      file_size: file.size,
    },
  });
  progress("Generating ephemeral X25519 key");
  const pair = await generateEphemeral();
  const sessionIdentifier = crypto.randomUUID();
  auth.vault.sessions[sessionIdentifier] = {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    transferId: transfer.id,
  };
  await auth.persist();
  const metadata = {
    protocol: PROTOCOL,
    purpose: "dh-initiate",
    transfer_id: transfer.id,
    session_identifier: sessionIdentifier,
    sender_id: auth.user.id,
    receiver_id: receiverId,
    sender_ephemeral_public_key: pair.publicKey,
    receiver_ephemeral_public_key: null,
    timestamp: timestamp(),
    nonce: nonce(),
  };
  await api("/sessions/initiate", {
    method: "POST",
    token: auth.token,
    data: {
      metadata,
      signature: await sign(auth.vault.identityPrivate, metadata),
    },
  });
  progress("Waiting for receiver to accept key exchange");
  return transfer;
}

export async function respondToSession(auth, session) {
  if (session.expires_at * 1000 <= Date.now())
    throw new Error(
      "This key exchange has expired. Ask the sender to start again.",
    );
  await verifySession(auth, session, { responded: false });
  const pair = await generateEphemeral();
  auth.vault.sessions[session.session_identifier] = {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    transferId: session.transfer_id,
  };
  await auth.persist();
  const metadata = {
    ...session.sender_metadata,
    purpose: "dh-respond",
    receiver_ephemeral_public_key: pair.publicKey,
    timestamp: timestamp(),
    nonce: nonce(),
  };
  return api(`/sessions/${session.id}/respond`, {
    method: "POST",
    token: auth.token,
    data: {
      metadata,
      signature: await sign(auth.vault.identityPrivate, metadata),
    },
  });
}

export async function uploadTransfer(auth, transfer, file, progress) {
  if (
    file.size !== transfer.file_size ||
    file.name !== transfer.original_filename
  )
    throw new Error(
      "Select the original file with the same filename and size.",
    );
  const session = transfer.session;
  const local = auth.vault.sessions[session.session_identifier];
  if (!local)
    throw new Error(
      "Local ephemeral key is missing. Restore your latest vault backup or start a new transfer.",
    );
  progress("Verifying both RSA key exchange signatures");
  await verifySession(auth, session);
  const transcript = await transcriptHash(session);
  if (session.status === "RESPONDED") {
    const metadata = {
      protocol: PROTOCOL,
      purpose: "dh-confirm",
      transfer_id: transfer.id,
      session_identifier: session.session_identifier,
      transcript_sha256: transcript,
      timestamp: timestamp(),
      nonce: nonce(),
    };
    await api(`/sessions/${session.id}/verify`, {
      method: "POST",
      token: auth.token,
      data: {
        metadata,
        signature: await sign(auth.vault.identityPrivate, metadata),
      },
    });
  }
  progress("Deriving AES-256 key with HKDF");
  const key = await deriveAES(
    local.privateKey,
    session.receiver_metadata.receiver_ephemeral_public_key,
    session,
  );
  const plaintext = new Uint8Array(await file.arrayBuffer());
  progress("Computing SHA-256 fingerprint");
  const metadata = {
    protocol: PROTOCOL,
    purpose: "file-transfer",
    transfer_id: transfer.id,
    session_identifier: session.session_identifier,
    sender_id: transfer.sender_id,
    receiver_id: transfer.receiver_id,
    filename: transfer.safe_filename,
    mime_type: transfer.mime_type,
    file_size: file.size,
    plaintext_sha256: await sha256(plaintext),
    transcript_sha256: transcript,
    nonce: b64(crypto.getRandomValues(new Uint8Array(12))),
    timestamp: timestamp(),
  };
  progress("Encrypting file with AES-256-GCM");
  const ciphertext = await encryptFile(key, plaintext, metadata);
  plaintext.fill(0);
  metadata.ciphertext_sha256 = await sha256(ciphertext);
  progress("Signing transfer metadata with RSA-PSS");
  const signature = await sign(auth.vault.identityPrivate, metadata);
  progress("Uploading ciphertext only");
  const result = await api(`/transfers/${transfer.id}/upload`, {
    method: "POST",
    token: auth.token,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Transfer-Metadata": b64(bytes(canonical(metadata))),
      "X-Transfer-Signature": signature,
    },
    body: ciphertext,
  });
  progress("Encrypted file available to receiver");
  return result;
}

export async function receiveTransfer(
  auth,
  transfer,
  progress,
  replayWindowSeconds = 300,
) {
  const session = transfer.session;
  const local = auth.vault.sessions[session.session_identifier];
  if (!local)
    throw new Error(
      "Local ephemeral key is missing. Restore the vault backup from this exchange.",
    );
  if (
    transfer.status !== "COMPLETED" &&
    session.expires_at * 1000 <= Date.now()
  )
    throw new Error(
      "Transfer session expired. Ask the sender for a new transfer.",
    );
  async function report(result, hash = null) {
    if (transfer.status === "COMPLETED") return;
    const metadata = {
      protocol: PROTOCOL,
      purpose: "transfer-receipt",
      transfer_id: transfer.id,
      receiver_id: auth.user.id,
      result,
      plaintext_sha256: hash,
      timestamp: timestamp(),
      nonce: nonce(),
    };
    await api(`/transfers/${transfer.id}/verify`, {
      method: "POST",
      token: auth.token,
      data: {
        metadata,
        signature: await sign(auth.vault.identityPrivate, metadata),
      },
    });
  }
  progress("Verifying authenticated key exchange");
  let senderKey;
  try {
    senderKey = await verifySession(auth, session);
  } catch (error) {
    await report("FAILED");
    throw error;
  }
  const transcript = await transcriptHash(session);
  const confirmation = session.confirmation_metadata;
  if (
    !confirmation ||
    confirmation.protocol !== PROTOCOL ||
    confirmation.purpose !== "dh-confirm" ||
    confirmation.transfer_id !== transfer.id ||
    confirmation.session_identifier !== session.session_identifier ||
    confirmation.transcript_sha256 !== transcript ||
    !(await verify(senderKey, session.confirmation_signature, confirmation))
  ) {
    await report("FAILED");
    throw new Error("Sender transcript confirmation is invalid.");
  }
  progress("Verifying RSA-PSS file signature");
  if (!(await verify(senderKey, transfer.signature, transfer.metadata))) {
    await report("SIGNATURE_INVALID");
    throw new Error("Sender file signature is invalid.");
  }
  const m = transfer.metadata;
  if (
    m.protocol !== PROTOCOL ||
    m.purpose !== "file-transfer" ||
    m.transfer_id !== transfer.id ||
    m.sender_id !== transfer.sender_id ||
    m.receiver_id !== auth.user.id ||
    m.session_identifier !== session.session_identifier ||
    m.transcript_sha256 !== transcript ||
    m.filename !== transfer.safe_filename ||
    m.file_size !== transfer.file_size ||
    m.mime_type !== transfer.mime_type
  ) {
    await report("TAMPERED");
    throw new Error("Signed file context does not match this transfer.");
  }
  if (
    m.timestamp * 1000 > Date.now() + replayWindowSeconds * 1000 ||
    m.timestamp < Math.floor(session.created_at) - replayWindowSeconds ||
    m.timestamp > session.expires_at
  ) {
    await report("FAILED");
    throw new Error("Signed transfer timestamp is invalid.");
  }
  progress("Downloading encrypted package");
  const ciphertext = await api(`/transfers/${transfer.id}/download`, {
    token: auth.token,
    binary: true,
  });
  let plaintext, failure;
  try {
    if ((await sha256(ciphertext)) !== m.ciphertext_sha256)
      throw new Error("Ciphertext fingerprint mismatch.");
    progress("Decrypting AES-256-GCM and checking authentication tag");
    const key = await deriveAES(
      local.privateKey,
      session.sender_metadata.sender_ephemeral_public_key,
      session,
    );
    plaintext = await decryptFile(key, ciphertext, m);
    progress("Checking plaintext SHA-256 fingerprint");
    if (
      plaintext.length !== transfer.file_size ||
      (await sha256(plaintext)) !== m.plaintext_sha256
    )
      throw new Error("Plaintext fingerprint mismatch.");
  } catch (error) {
    failure = error;
  }
  await report(
    failure ? "TAMPERED" : "VERIFIED",
    failure ? null : m.plaintext_sha256,
  );
  if (failure) {
    plaintext?.fill(0);
    throw new Error(
      "File rejected: AES authentication or fingerprint verification failed.",
    );
  }
  progress("All checks passed · transfer completed");
  return {
    plaintext,
    filename: transfer.safe_filename,
    mimeType: transfer.mime_type,
  };
}

export function downloadBytes(
  content,
  filename,
  mimeType = "application/octet-stream",
) {
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
