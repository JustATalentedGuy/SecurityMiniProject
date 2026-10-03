import { webcrypto } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  aad,
  b64,
  bytes,
  canonical,
  decryptFile,
  deriveAES,
  encryptFile,
  generateEphemeral,
  generateIdentity,
  nonce,
  sha256,
  sign,
  unb64,
  verify,
} from "./crypto";
import { openVault, sealVault } from "../services/vault";

beforeAll(() => {
  if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
});

describe("cross-platform cryptographic protocol", () => {
  it("canonicalizes Unicode exactly like Python ASCII JSON", () => {
    expect(canonical({ z: "é😀", a: 1 })).toBe(
      '{"a":1,"z":"\\u00e9\\ud83d\\ude00"}',
    );
    expect(canonical({ b: { z: 2, a: 1 }, a: null })).toBe(
      '{"a":null,"b":{"a":1,"z":2}}',
    );
  });
  it("matches SHA-256 known answers and round-trips binary base64", async () => {
    expect(await sha256(bytes("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    const data = new Uint8Array([0, 255, 127, 1]);
    expect(unb64(b64(data))).toEqual(data);
    expect(nonce()).toMatch(/^[a-f0-9]{32}$/);
    expect(nonce()).not.toBe(nonce());
  });
  it("signs and rejects altered RSA metadata", async () => {
    const identity = await generateIdentity();
    const metadata = { purpose: "test", nonce: nonce() };
    const signature = await sign(identity.identityPrivate, metadata);
    expect(await verify(identity.publicKeyPem, signature, metadata)).toBe(true);
    expect(
      await verify(identity.publicKeyPem, signature, {
        ...metadata,
        purpose: "forged",
      }),
    ).toBe(false);
    expect(await verify(identity.publicKeyPem, "invalid", metadata)).toBe(
      false,
    );
  });
  it("derives identical keys, authenticates ciphertext and AAD, separates sessions", async () => {
    const alice = await generateEphemeral();
    const bob = await generateEphemeral();
    const session = {
      session_identifier: "session-one",
      sender_metadata: { key: alice.publicKey },
      receiver_metadata: { key: bob.publicKey },
    };
    const ka = await deriveAES(alice.privateKey, bob.publicKey, session);
    const kb = await deriveAES(bob.privateKey, alice.publicKey, session);
    const metadata = {
      nonce: b64(crypto.getRandomValues(new Uint8Array(12))),
      filename: "hello.txt",
    };
    const plaintext = bytes("hello\0secret");
    const ciphertext = await encryptFile(ka, plaintext, metadata);
    expect(
      await decryptFile(kb, ciphertext, {
        ...metadata,
        ciphertext_sha256: await sha256(ciphertext),
      }),
    ).toEqual(plaintext);
    expect(aad(metadata)).toEqual(
      aad({ ...metadata, ciphertext_sha256: "irrelevant" }),
    );
    const tampered = ciphertext.slice();
    tampered[0] ^= 1;
    await expect(decryptFile(kb, tampered, metadata)).rejects.toThrow();
    await expect(
      decryptFile(kb, ciphertext, { ...metadata, filename: "changed.txt" }),
    ).rejects.toThrow();
    const otherKey = await deriveAES(bob.privateKey, alice.publicKey, {
      ...session,
      session_identifier: "session-two",
    });
    await expect(decryptFile(otherKey, ciphertext, metadata)).rejects.toThrow();
  });
  it("encrypts local vaults and rejects wrong passwords and corruption", async () => {
    const identity = await generateIdentity();
    const vault = { username: "alice", ...identity, sessions: {}, pins: {} };
    const envelope = await sealVault(vault, "test-vault-password");
    expect(envelope.ciphertext).not.toContain(identity.identityPrivate);
    expect(await openVault(envelope, "test-vault-password")).toEqual(vault);
    await expect(openVault(envelope, "wrong-password")).rejects.toThrow(
      "Unable to unlock",
    );
    const data = unb64(envelope.ciphertext);
    data[0] ^= 1;
    await expect(
      openVault({ ...envelope, ciphertext: b64(data) }, "test-vault-password"),
    ).rejects.toThrow();
    await expect(
      openVault(
        { ...envelope, kdf: { ...envelope.kdf, iterations: 1 } },
        "test-vault-password",
      ),
    ).rejects.toThrow("Unsupported");
  });
});
