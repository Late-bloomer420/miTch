import assert from "assert";
import { generateKeyPairSync, sign } from "crypto";
import { verifyRequest } from "../api/verifierRoutes";
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
const keyId = "kid-evidence-1";

const activeResolver: ResolveKey = async (kid?: string) => {
  if (kid !== keyId) return { status: "missing" };
  return { status: "active", publicKeyPem };
};

const revokedResolver: ResolveKey = async () => ({ status: "revoked" });

function buildRequest(): VerificationRequestV0 {
  const r: VerificationRequestV0 = {
    version: "v0",
    requestId: `ev-${Date.now()}-${Math.random()}`,
    rp: { id: "rp.example", audience: "rp.example" },
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
  const hash = computeRequestHash(r);
  r.binding.requestHash = hash;
  r.proofBundle.proof = b64u(sign(null, Buffer.from(hash, "utf8"), privateKey));
  return r;
}

export async function runEvidenceScenarios(): Promise<{ generatedAt: string; results: Array<{ scenario: string; code: string }> }> {
  const results: Array<{ scenario: string; code: string }> = [];

  // 1) ALLOW
  const allowReq = buildRequest();
  const allow = await verifyRequest(allowReq, policy, "rp.example", activeResolver);
  results.push({ scenario: "allow_valid", code: allow.decisionCode });
  assert.equal(allow.decisionCode, "ALLOW_MINIMAL_PROOF_VALID");

  // 2) DENY replay
  const replayReq = buildRequest();
  await verifyRequest(replayReq, policy, "rp.example", activeResolver);
  const replay = await verifyRequest(replayReq, policy, "rp.example", activeResolver);
  results.push({ scenario: "deny_replay", code: replay.decisionCode });
  assert.equal(replay.decisionCode, "DENY_BINDING_NONCE_REPLAY");

  // 3) DENY hash mismatch
  const hashReq = buildRequest();
  hashReq.binding.requestHash = "tampered";
  const hashMismatch = await verifyRequest(hashReq, policy, "rp.example", activeResolver);
  results.push({ scenario: "deny_hash_mismatch", code: hashMismatch.decisionCode });
  assert.equal(hashMismatch.decisionCode, "DENY_BINDING_HASH_MISMATCH");

  // 4) DENY revoked key
  const revokedReq = buildRequest();
  const revoked = await verifyRequest(revokedReq, policy, "rp.example", revokedResolver);
  results.push({ scenario: "deny_revoked_key", code: revoked.decisionCode });
  assert.equal(revoked.decisionCode, "DENY_CRYPTO_KEY_STATUS_INVALID");

  // 5) DENY missing key
  const missingResolver: ResolveKey = async () => ({ status: "missing" });
  const missingReq = buildRequest();
  const missing = await verifyRequest(missingReq, policy, "rp.example", missingResolver);
  results.push({ scenario: "deny_missing_key", code: missing.decisionCode });
  assert.equal(missing.decisionCode, "DENY_CRYPTO_KEY_STATUS_INVALID");

  // 6) DENY unsupported alg
  const algReq = buildRequest();
  algReq.proofBundle.alg = "RS256";
  const wrongAlg = await verifyRequest(algReq, policy, "rp.example", activeResolver);
  results.push({ scenario: "deny_unsupported_alg", code: wrongAlg.decisionCode });
  assert.equal(wrongAlg.decisionCode, "DENY_CRYPTO_UNSUPPORTED_ALG");

  return { generatedAt: new Date().toISOString(), results };
}

if (require.main === module) {
  runEvidenceScenarios()
    .then((out) => console.log(JSON.stringify(out, null, 2)))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
