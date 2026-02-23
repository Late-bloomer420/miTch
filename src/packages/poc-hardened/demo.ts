import { generateKeyPairSync, sign } from "crypto";
import { verifyRequest } from "./api/verifierRoutes";
import { computeRequestHash } from "./binding/requestHash";
import { VerificationRequestV0 } from "./types/api";
import { PolicyManifestV0 } from "./types/policy";
import { ResolveKey } from "./proof/keyResolver";

function toBase64Url(buffer: Buffer): string {
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

const keyId = "kid-demo-1";

const resolveKey: ResolveKey = async (kid?: string) => {
  if (kid !== keyId) return { status: "missing" };
  return { status: "active", publicKeyPem };
};

const requestBase: Omit<VerificationRequestV0, "binding" | "proofBundle"> = {
  version: "v0",
  requestId: "req-1",
  rp: { id: "rp.example", audience: "rp.example" },
  purpose: "age_gate_checkout",
  claims: [{ type: "predicate", name: "age_gte", value: 18 }],
  policyRef: "policy-v0-age",
};

async function run(): Promise<void> {
  const provisional: VerificationRequestV0 = {
    ...requestBase,
    proofBundle: { format: "sd-jwt-vc", proof: "", keyId, alg: "EdDSA" },
    binding: {
      nonce: "nonce-1",
      requestHash: "",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
  };

  const requestHash = computeRequestHash(provisional);
  const signature = sign(null, Buffer.from(requestHash, "utf8"), privateKey);

  const request: VerificationRequestV0 = {
    ...provisional,
    proofBundle: {
      ...provisional.proofBundle,
      proof: toBase64Url(signature),
    },
    binding: {
      ...provisional.binding,
      requestHash,
    },
  };

  const result = await verifyRequest(request, policy, "rp.example", resolveKey);
  console.log(result);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
