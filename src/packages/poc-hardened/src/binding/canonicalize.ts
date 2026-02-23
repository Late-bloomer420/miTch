import { VerificationRequestV0 } from "../types/api";

function normalize(value: unknown): unknown {
  if (typeof value === "string") return value.normalize("NFC");
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = normalize(obj[key]);
    }
    return out;
  }
  return value;
}

export function canonicalPayload(request: VerificationRequestV0): Record<string, unknown> {
  return normalize({
    version: request.version,
    requestId: request.requestId,
    rp: {
      id: request.rp.id,
      audience: request.rp.audience,
    },
    purpose: request.purpose,
    claims: request.claims,
    policyRef: request.policyRef,
    binding: {
      nonce: request.binding.nonce,
      expiresAt: request.binding.expiresAt,
    },
  }) as Record<string, unknown>;
}

export function canonicalizeRequest(request: VerificationRequestV0): string {
  return JSON.stringify(canonicalPayload(request));
}
