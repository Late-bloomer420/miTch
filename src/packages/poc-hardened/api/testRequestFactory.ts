import { generateKeyPairSync, sign } from "crypto";
import { computeRequestHash } from "../binding/requestHash";
import { ResolveKey } from "../proof/keyResolver";
import { VerificationRequestV0 } from "../types/api";

function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
const keyId = "kid-http-local-1";

export const localResolveKey: ResolveKey = async (kid?: string) => {
  if (kid !== keyId) return { status: "missing" };
  return { status: "active", publicKeyPem };
};

export function createSignedLocalRequest(audience = "rp.example"): VerificationRequestV0 {
  const req: VerificationRequestV0 = {
    version: "v0",
    requestId: `req-http-${Date.now()}-${Math.random()}`,
    rp: { id: "rp.example", audience },
    purpose: "age_gate_checkout",
    claims: [{ type: "predicate", name: "age_gte", value: 18 }],
    proofBundle: {
      format: "sd-jwt-vc",
      proof: "",
      keyId,
      alg: "EdDSA",
    },
    binding: {
      nonce: `nonce-http-${Date.now()}-${Math.random()}`,
      requestHash: "",
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    },
    policyRef: "policy-v0-age",
  };

  const hash = computeRequestHash(req);
  const sig = sign(null, Buffer.from(hash, "utf8"), privateKey);
  req.binding.requestHash = hash;
  req.proofBundle.proof = toBase64Url(sig);

  return req;
}
