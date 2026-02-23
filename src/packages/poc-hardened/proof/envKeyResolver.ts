import { ResolveKey } from "./keyResolver";
import { StaticStatusProvider } from "./statusProvider";
import { createKeySource } from "./keySource";
import { getLastResolverOutcome } from "./httpKeySource";

const statusProvider = new StaticStatusProvider();
const keySource = createKeySource();

export const envResolveKey: ResolveKey = async (keyId?: string) => {
  const status = await statusProvider.getStatus(keyId);
  if (!keyId) return { status: "missing" };
  if (status === "revoked") return { status: "revoked" };
  if (status === "unavailable") return { status: "unavailable" };

  const pem = await keySource.getPublicKeyPem(keyId);
  if (!pem) {
    const mode = (process.env.KEY_SOURCE_MODE ?? "env").toLowerCase();
    if (mode === "http") {
      const outcome = getLastResolverOutcome(keyId);
      if (outcome === "quorum_failed") return { status: "resolver_quorum_failed" };
    }
    return { status: "missing" };
  }
  return { status: "active", publicKeyPem: pem };
};
