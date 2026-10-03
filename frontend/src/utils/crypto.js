export const PROTOCOL = "secureshare-x/v1";
const encoder = new TextEncoder();
export const bytes = (text) => encoder.encode(text);

export function canonical(value) {
  // Match Python ensure_ascii=True, including UTF-16 surrogate pairs.
  const sort = (item) =>
    Array.isArray(item)
      ? item.map(sort)
      : item && typeof item === "object"
        ? Object.fromEntries(
            Object.keys(item)
              .sort()
              .map((key) => [key, sort(item[key])]),
          )
        : item;
  return JSON.stringify(sort(value)).replace(
    /[\u007f-\uffff]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function b64(value) {
  const data = new Uint8Array(value);
  let result = "";
  for (let i = 0; i < data.length; i += 8192)
    result += String.fromCharCode(...data.subarray(i, i + 8192));
  return btoa(result);
}
export const unb64 = (value) =>
  Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
export const hex = (value) =>
  Array.from(new Uint8Array(value), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
export const nonce = () => hex(crypto.getRandomValues(new Uint8Array(16)));
export const timestamp = () => Math.floor(Date.now() / 1000);
export const sha256 = async (value) =>
  hex(await crypto.subtle.digest("SHA-256", value));
export const fromHex = (value) =>
  Uint8Array.from(value.match(/.{2}/g), (item) => parseInt(item, 16));
export const pemBytes = (pem) =>
  unb64(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""));

export async function generateIdentity() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 3072,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const publicData = b64(await crypto.subtle.exportKey("spki", pair.publicKey));
  return {
    identityPrivate: b64(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey),
    ),
    publicKeyPem: `-----BEGIN PUBLIC KEY-----\n${publicData.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`,
  };
}

export const importIdentity = (privateData) =>
  crypto.subtle.importKey(
    "pkcs8",
    unb64(privateData),
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"],
  );
export async function sign(privateData, metadata) {
  return b64(
    await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      await importIdentity(privateData),
      bytes(canonical(metadata)),
    ),
  );
}
export async function verify(publicKeyPem, signature, metadata) {
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      pemBytes(publicKeyPem),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      key,
      unb64(signature),
      bytes(canonical(metadata)),
    );
  } catch {
    return false;
  }
}

export async function generateEphemeral() {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ]);
  return {
    privateKey: b64(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
    publicKey: b64(await crypto.subtle.exportKey("raw", pair.publicKey)),
  };
}

export const transcriptHash = (session) =>
  sha256(
    bytes(
      canonical({
        sender: session.sender_metadata,
        receiver: session.receiver_metadata,
      }),
    ),
  );

export async function deriveAES(privateKey, peerPublic, session) {
  const local = await crypto.subtle.importKey(
    "pkcs8",
    unb64(privateKey),
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  const peer = await crypto.subtle.importKey(
    "raw",
    unb64(peerPublic),
    { name: "X25519" },
    false,
    [],
  );
  const secret = await crypto.subtle.deriveBits(
    { name: "X25519", public: peer },
    local,
    256,
  );
  const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveKey",
  ]);
  new Uint8Array(secret).fill(0);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: fromHex(await transcriptHash(session)),
      info: bytes(`${PROTOCOL}/aes256gcm/${session.session_identifier}`),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function aad(metadata) {
  const { ciphertext_sha256: _ciphertextHash, ...associated } = metadata;
  return bytes(canonical(associated));
}
export async function encryptFile(key, plaintext, metadata) {
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: unb64(metadata.nonce),
      additionalData: aad(metadata),
      tagLength: 128,
    },
    key,
    plaintext,
  );
  return new Uint8Array(ciphertext);
}
export async function decryptFile(key, ciphertext, metadata) {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(metadata.nonce),
        additionalData: aad(metadata),
        tagLength: 128,
      },
      key,
      ciphertext,
    ),
  );
}
