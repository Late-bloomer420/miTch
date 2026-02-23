import { VerificationRequestV0 } from "../types/api";

export function validateRequestSemantics(r: VerificationRequestV0): { ok: true } | { ok: false; code: string } {
  if (!r.rp || typeof r.rp.id !== "string" || typeof r.rp.audience !== "string") {
    return { ok: false, code: "DENY_SCHEMA_TYPE_MISMATCH" };
  }

  if (!Array.isArray(r.claims) || r.claims.length === 0) {
    return { ok: false, code: "DENY_SCHEMA_MISSING_FIELD" };
  }

  for (const c of r.claims) {
    if (c.type !== "predicate") return { ok: false, code: "DENY_SCHEMA_TYPE_MISMATCH" };
    if (typeof c.name !== "string" || c.name.length === 0) return { ok: false, code: "DENY_SCHEMA_MISSING_FIELD" };
  }

  if (!r.binding || typeof r.binding.nonce !== "string" || typeof r.binding.requestHash !== "string") {
    return { ok: false, code: "DENY_SCHEMA_MISSING_FIELD" };
  }

  if (!r.proofBundle || typeof r.proofBundle.format !== "string" || typeof r.proofBundle.alg !== "string") {
    return { ok: false, code: "DENY_SCHEMA_MISSING_FIELD" };
  }

  if (r.rp.jurisdiction !== undefined && (typeof r.rp.jurisdiction !== "string" || r.rp.jurisdiction.length === 0)) {
    return { ok: false, code: "DENY_SCHEMA_TYPE_MISMATCH" };
  }

  return { ok: true };
}
