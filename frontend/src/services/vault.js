import { b64, bytes, unb64 } from "../utils/crypto";

const VAULT_CONTEXT = bytes("secureshare-x/vault/v1");
export const vaultKey = (username) => `ssx:vault:${username.toLowerCase()}`;

async function passwordKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    bytes(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", iterations, salt },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export async function sealVault(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 600000;
  const key = await passwordKey(password, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: VAULT_CONTEXT },
    key,
    bytes(JSON.stringify(data)),
  );
  return {
    version: 1,
    username: data.username,
    kdf: { name: "PBKDF2-SHA256", iterations, salt: b64(salt) },
    nonce: b64(iv),
    ciphertext: b64(ciphertext),
  };
}
export async function openVault(envelope, password) {
  if (
    envelope.version !== 1 ||
    envelope.kdf?.name !== "PBKDF2-SHA256" ||
    envelope.kdf.iterations !== 600000 ||
    unb64(envelope.kdf.salt).length !== 16 ||
    unb64(envelope.nonce).length !== 12 ||
    envelope.ciphertext.length > 4 * 1024 * 1024
  )
    throw new Error("Unsupported or invalid encrypted key vault.");
  try {
    const key = await passwordKey(
      password,
      unb64(envelope.kdf.salt),
      envelope.kdf.iterations,
    );
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(envelope.nonce),
        additionalData: VAULT_CONTEXT,
      },
      key,
      unb64(envelope.ciphertext),
    );
    const data = JSON.parse(new TextDecoder().decode(plaintext));
    if (
      data.username !== envelope.username ||
      !data.identityPrivate ||
      !data.publicKeyPem ||
      !data.sessions ||
      !data.pins
    )
      throw new Error("Invalid vault");
    return data;
  } catch {
    throw new Error(
      "Unable to unlock the key vault. Check your password and backup file.",
    );
  }
}
export async function saveVault(data, password) {
  const envelope = await sealVault(data, password);
  localStorage.setItem(vaultKey(data.username), JSON.stringify(envelope));
  return envelope;
}
export function loadEnvelope(username) {
  const item = localStorage.getItem(vaultKey(username));
  return item ? JSON.parse(item) : null;
}
