import assert from "assert";
import { generateKeyPairSync, sign } from "crypto";
import { verifyRequest } from "../api/verifierRoutes";
import { resetRateLimiter } from "../api/rateLimiter";
import { computeRequestHash } from "../binding/requestHash";
import { VerificationRequestV0 } from "../types/api";
import { PolicyManifestV0 } from "../types/policy";
import { ResolveKey } from "../proof/keyResolver";

function b64u(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

const policy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
const keyId = "kid-swarm-1";

const activeResolver: ResolveKey = async (kid?: string) => {
  if (kid !== keyId) return { status: "missing" };
  return { status: "active", publicKeyPem };
};

function buildRequest(rpId: string): VerificationRequestV0 {
  const req: VerificationRequestV0 = {
    version: "v0",
    requestId: `swarm-${Date.now()}-${Math.random()}`,
    rp: { id: rpId, audience: "rp.example" },
    purpose: "age_gate_checkout",
    claims: [{ type: "predicate", name: "age_gte", value: 18 }],
    proofBundle: { format: "sd-jwt-vc", proof: "", keyId, alg: "EdDSA" },
    binding: {
      nonce: `nonce-${Date.now()}-${Math.random()}`,
      requestHash: "",
      expiresAt: new Date(Date.now() + 120000).toISOString(),
    },
    policyRef: "policy-v0-age",
  };

  const hash = computeRequestHash(req);
  req.binding.requestHash = hash;
  req.proofBundle.proof = b64u(sign(null, Buffer.from(hash, "utf8"), privateKey));
  return req;
}

async function run(): Promise<void> {
  process.env.MAX_REQUESTS_GLOBAL = "30";

  // Scenario A: burst from same requester (rate limiting expected)
  resetRateLimiter();
  const sameRequester = Array.from({ length: 60 }, () =>
    verifyRequest(buildRequest("rp.swarm.same"), policy, "rp.example", activeResolver)
  );
  const sameResults = await Promise.all(sameRequester);
  const sameDeniedRateLimit = sameResults.filter((r) => r.decisionCode === "DENY_RATE_LIMIT_EXCEEDED").length;

  // Scenario B: distributed swarm (unique requester ids) - should hit global limit
  resetRateLimiter();
  const distributed = Array.from({ length: 60 }, (_, i) =>
    verifyRequest(buildRequest(`rp.swarm.${i}`), policy, "rp.example", activeResolver)
  );
  const distResults = await Promise.all(distributed);
  const distDeniedRateLimit = distResults.filter((r) => r.decisionCode === "DENY_RATE_LIMIT_EXCEEDED").length;

  // Assertions for current model behavior
  assert.ok(sameDeniedRateLimit > 0, "Expected rate-limit denies for same requester burst");
  assert.ok(distDeniedRateLimit > 0, "Expected distributed burst to hit global limit");

  console.log(
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        scenario_same_requester: {
          total: sameResults.length,
          deny_rate_limit: sameDeniedRateLimit,
        },
        scenario_distributed_requesters: {
          total: distResults.length,
          deny_rate_limit: distDeniedRateLimit,
        },
        note: "Global request budget baseline added; distributed swarm now triggers rate-limit denies.",
      },
      null,
      2
    )
  );
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
