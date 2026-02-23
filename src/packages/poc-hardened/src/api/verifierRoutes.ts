import { VerificationRequestV0, VerificationResponseV0 } from "../types/api";
import { PolicyManifestV0 } from "../types/policy";
import { InMemoryNonceStore } from "../binding/nonceStore";
import { validateBinding } from "../binding/validateBinding";
import { evaluatePolicy } from "../policy/evaluator";
import { verifyProofBundle } from "../proof/verifier";
import { ResolveKey } from "../proof/keyResolver";
import { validateRequestShape } from "./schemaValidator";
import { checkRateLimit } from "./rateLimiter";
import { appendReceipt } from "../receipt/wormWriter";
import { validateRequestSemantics } from "./requestGuards";
import { shouldFailClosedOnStatusUnavailable } from "../config/revocation";
import { checkProofFatigue, getProofFatigueConfig } from "./proofFatigue";

const nonceStore = new InMemoryNonceStore();

function deny(requestId: string, decisionCode: string): VerificationResponseV0 {
  const verifiedAt = new Date().toISOString();
  const receiptRef = appendReceipt({ requestId, decision: "DENY", decisionCode, verifiedAt });
  return {
    version: "v0",
    requestId,
    decision: "DENY",
    decisionCode,
    claimsSatisfied: [],
    receiptRef,
    verifiedAt,
  };
}

/**
 * Minimal verifier orchestration for MVP scaffolding.
 * Gate order: schema -> binding -> policy -> (crypto placeholder) -> receipt
 */
export async function verifyRequest(
  requestInput: unknown,
  policy: PolicyManifestV0,
  runtimeAudience: string,
  resolveKey: ResolveKey
): Promise<VerificationResponseV0> {
  const requestId =
    typeof requestInput === "object" && requestInput && "requestId" in requestInput
      ? String((requestInput as { requestId?: string }).requestId ?? "unknown")
      : "unknown";

  try {
    // schema gate
    const schema = validateRequestShape(requestInput);
    if (!schema.ok) return deny(requestId, schema.code);
    const request = schema.value;

    // semantic guard gate
    const sem = validateRequestSemantics(request);
    if (!sem.ok) return deny(request.requestId, sem.code);

    // optional jurisdiction compatibility gate
    if (process.env.REQUIRE_JURISDICTION_MATCH === "1") {
      const runtimeJurisdiction = (process.env.RUNTIME_JURISDICTION ?? "").trim();
      const requesterJurisdiction = (request.rp.jurisdiction ?? "").trim();
      if (!runtimeJurisdiction || !requesterJurisdiction || runtimeJurisdiction !== requesterJurisdiction) {
        return deny(request.requestId, "DENY_JURISDICTION_INCOMPATIBLE");
      }
    }

    // rate-limit gate
    const allowed = checkRateLimit(request.rp.id, {
      windowSeconds: 60,
      maxRequestsPerRequester: 10,
      maxRequestsGlobal: Number(process.env.MAX_REQUESTS_GLOBAL ?? 100),
    });
    if (!allowed) return deny(request.requestId, "DENY_RATE_LIMIT_EXCEEDED");

    // proof-fatigue gate for repeated high-risk prompts
    const fatigue = checkProofFatigue(request, getProofFatigueConfig());
    if (!fatigue.allowed) return deny(request.requestId, fatigue.reason ?? "DENY_REAUTH_REQUIRED");

    // binding gate
    const binding = await validateBinding(request, runtimeAudience, nonceStore, {
      clockSkewSeconds: 90,
      nonceTtlSeconds: 600,
    });

    if (!binding.ok) return deny(request.requestId, binding.code ?? "DENY_INTERNAL_SAFE_FAILURE");

    // policy gate
    const decision = evaluatePolicy(request, policy);
    if (decision.decision === "DENY") return deny(request.requestId, decision.decisionCode);

    // crypto verify gate (MVP stub wired in)
    const crypto = await verifyProofBundle(request.proofBundle, request.binding.requestHash, resolveKey);
    if (!crypto.ok) {
      if (crypto.reason === "unsupported_alg") return deny(request.requestId, "DENY_CRYPTO_UNSUPPORTED_ALG");
      if (crypto.reason === "revoked_key") return deny(request.requestId, "DENY_CRYPTO_KEY_STATUS_INVALID");
      if (crypto.reason === "resolver_quorum_failed") return deny(request.requestId, "DENY_RESOLVER_QUORUM_FAILED");
      if (crypto.reason === "revoked_credential") return deny(request.requestId, "DENY_CREDENTIAL_REVOKED");
      if (crypto.reason === "credential_status_invalid") return deny(request.requestId, "DENY_CREDENTIAL_STATUS_INVALID");
      if (crypto.reason === "missing_key") return deny(request.requestId, "DENY_CRYPTO_KEY_STATUS_INVALID");
      if (crypto.reason === "status_unavailable" || crypto.reason === "credential_status_unavailable") {
        return shouldFailClosedOnStatusUnavailable(request.purpose)
          ? deny(request.requestId, "DENY_STATUS_SOURCE_UNAVAILABLE")
          : deny(request.requestId, "DENY_STATUS_SOURCE_UNAVAILABLE");
      }
      return deny(request.requestId, "DENY_CRYPTO_VERIFY_FAILED");
    }

    const verifiedAt = new Date().toISOString();
    const receiptRef = appendReceipt({
      requestId: request.requestId,
      decision: "ALLOW",
      decisionCode: "ALLOW_MINIMAL_PROOF_VALID",
      verifiedAt,
    });

    return {
      version: "v0",
      requestId: request.requestId,
      decision: "ALLOW",
      decisionCode: "ALLOW_MINIMAL_PROOF_VALID",
      claimsSatisfied: decision.claimsSatisfied,
      receiptRef,
      verifiedAt,
    };
  } catch {
    return deny(requestId, "DENY_INTERNAL_SAFE_FAILURE");
  }
}
