import { verify } from "crypto";
import { ProofBundleV0 } from "../types/api";
import { ResolveKey } from "./keyResolver";
import { checkCredentialRevocation } from "./credentialStatus";

function getAllowedAlgs(): Set<string> {
  return new Set(
    (process.env.ALLOWED_ALGS ?? "EdDSA")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

function base64UrlToBuffer(input: string): Buffer {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

export async function verifyProofBundle(
  bundle: ProofBundleV0,
  message: string,
  resolveKey: ResolveKey
): Promise<{ ok: boolean; reason?: string }> {
  if (!bundle || typeof bundle !== "object") return { ok: false, reason: "missing_bundle" };
  if (!bundle.proof || bundle.proof.trim().length === 0) return { ok: false, reason: "empty_proof" };
  const allowedAlgs = getAllowedAlgs();
  if (!bundle.alg || !allowedAlgs.has(bundle.alg)) return { ok: false, reason: "unsupported_alg" };

  const credentialStatus = await checkCredentialRevocation(bundle.credentialId, bundle.credentialStatus);
  if (!credentialStatus.ok) return { ok: false, reason: credentialStatus.reason };
  if (credentialStatus.revoked) return { ok: false, reason: "revoked_credential" };

  const key = await resolveKey(bundle.keyId);
  if (key.status === "revoked") return { ok: false, reason: "revoked_key" };
  if (key.status === "resolver_quorum_failed") return { ok: false, reason: "resolver_quorum_failed" };
  if (key.status === "unavailable") return { ok: false, reason: "status_unavailable" };
  if (key.status !== "active" || !key.publicKeyPem) return { ok: false, reason: "missing_key" };

  try {
    const signature = base64UrlToBuffer(bundle.proof);
    const ok = verify(null, Buffer.from(message, "utf8"), key.publicKeyPem, signature);
    return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
  } catch {
    return { ok: false, reason: "verify_error" };
  }
}
