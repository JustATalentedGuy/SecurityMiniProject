import { createContext, useContext, useState } from "react";
import { api } from "../services/api";
import { generateIdentity, sign, sha256, pemBytes } from "../utils/crypto";
import { loadEnvelope, openVault, saveVault } from "../services/vault";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(null);
  async function authenticate({ username, password, mode, imported }) {
    username = username.toLowerCase();
    let vault;
    if (mode === "register") {
      vault = imported
        ? await openVault(imported, password)
        : {
            version: 1,
            username,
            ...(await generateIdentity()),
            sessions: {},
            pins: {},
          };
      if (vault.username !== username)
        throw new Error("This vault belongs to a different username.");
      await api("/auth/register", {
        method: "POST",
        data: { username, password, public_key_pem: vault.publicKeyPem },
      });
      await saveVault(vault, password);
    } else {
      const envelope = imported || loadEnvelope(username);
      if (!envelope)
        throw new Error(
          "No local identity found. Import your encrypted key vault backup, or register a new identity.",
        );
      vault = await openVault(envelope, password);
      if (vault.username !== username)
        throw new Error("This vault belongs to a different username.");
    }
    let result;
    if (mode === "challenge") {
      const challenge = await api("/auth/challenge", {
        method: "POST",
        data: { username },
      });
      result = await api("/auth/challenge/verify", {
        method: "POST",
        data: {
          challenge_id: challenge.id,
          signature: await sign(vault.identityPrivate, challenge.metadata),
        },
      });
    } else
      result = await api("/auth/login", {
        method: "POST",
        data: { username, password },
      });
    if (
      (await sha256(pemBytes(vault.publicKeyPem))) !== result.user.fingerprint
    )
      throw new Error(
        "Your vault identity differs from the registered public key. Restore the correct backup.",
      );
    const next = {
      token: result.access_token,
      user: result.user,
      vault,
      password,
      persist: () => saveVault(vault, password),
    };
    await next.persist();
    sessionStorage.setItem("ssx:token", next.token);
    setAuth(next);
    return next;
  }
  async function logout() {
    if (auth) {
      try {
        await api("/auth/logout", { method: "POST", token: auth.token });
      } catch {
        /* expiry also invalidates a session */
      }
    }
    sessionStorage.removeItem("ssx:token");
    setAuth(null);
  }
  return (
    <AuthContext.Provider value={{ auth, authenticate, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
export const useAuth = () => useContext(AuthContext);
