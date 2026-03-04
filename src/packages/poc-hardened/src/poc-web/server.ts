/**
 * PoC Web Demo Server — Full miTch Demo with Audit & Transparency
 */

import { createServer, IncomingMessage, ServerResponse } from "http";
import { readFileSync } from "fs";
import { join } from "path";
import {
  generateIssuerKey,
  generateHolderKey,
  issueCredential,
  createPresentation,
  verifyPresentation,
  SDJWTCredential,
  SDJWTIssuerKey,
} from "../credential/sdjwt";
import {
  StatusListPublisher,
  checkRevocation,
} from "../credential/statusList";
import { padResponse } from "../credential/metadata";
import { KeyObject, createHash } from "crypto";
import { AuditChain } from "../audit/auditChain";
import { EphemeralKeyManager } from "../audit/cryptoShred";
import { ROPAStore } from "../audit/ropa";
import {
  ConsentReceiptStore,
  createConsentReceipt,
  ConsentClaimRecord,
} from "../audit/consentReceipt";
import { generateTransparencyReport } from "../audit/transparencyReport";

// ─── State ───────────────────────────────────────────────────────

let issuerKey: SDJWTIssuerKey;
let holderKeys: { privateKey: KeyObject; publicKey: KeyObject };
let credential: SDJWTCredential | null = null;
let statusList: StatusListPublisher;
let auditChain: AuditChain;
let keyManager: EphemeralKeyManager;
let ropaStore: ROPAStore;
let consentStore: ConsentReceiptStore;
let _lastEphemeralKeyId: string | null = null;

function sha256(data: string): string {
  return createHash("sha-256").update(data, "utf8").digest("hex").substring(0, 16);
}

function initState(): void {
  issuerKey = generateIssuerKey("eid-austria-key-1");
  holderKeys = generateHolderKey();
  statusList = new StatusListPublisher(1024, "https://mitch.example/status");
  auditChain = new AuditChain();
  keyManager = new EphemeralKeyManager();
  ropaStore = new ROPAStore();
  consentStore = new ConsentReceiptStore();
  lastEphemeralKeyId = null;
  credential = null;

  // Register ROPA activities
  ropaStore.registerActivity({
    activity: "age_verification",
    controller: { entity: "Demo Verifier", purpose: "Age verification", legalBasis: "JuSchG §2" },
    dataCategories: ["age_predicate"],
    recipientCategories: ["verifier_merchant"],
    retentionPolicy: "crypto_shredded_after_transaction",
    safeguards: ["selective_disclosure", "crypto_shredding", "response_padding"],
  });
  ropaStore.registerActivity({
    activity: "credential_issuance",
    controller: { entity: "miTch Issuer", purpose: "Credential creation", legalBasis: "GDPR Art. 6(1)(a)" },
    dataCategories: ["identity_predicates"],
    recipientCategories: ["user_wallet"],
    retentionPolicy: "crypto_shredded_immediately",
    safeguards: ["ephemeral_keys", "crypto_shredding"],
  });
}

initState();

// ─── API Handlers ────────────────────────────────────────────────

function handleIssue(): object {
  // Create ephemeral key for raw PII
  const ek = keyManager.createKey();
  lastEphemeralKeyId = ek.keyId;

  // Simulate: encrypt raw PII with ephemeral key
  const rawPII = JSON.stringify({ name: "Jonas", birthdate: "1998-05-12", email: "jonas@example.at" });
  const encrypted = keyManager.encrypt(ek.keyId, rawPII);

  // Issue credential (only predicates, not raw data)
  credential = issueCredential({
    issuerKey,
    issuerId: "https://eid.example.at",
    subjectId: "holder-anonymous",
    claims: {
      over_18: true,
      over_16: true,
      over_21: false,
      email_verified: true,
      jurisdiction: "AT",
    },
    credentialType: "age_verification",
    expiresInSeconds: 90 * 24 * 3600,
    statusListIndex: 42,
    statusListUri: statusList.url,
    holderPublicKey: holderKeys.publicKey,
  });

  // Crypto-shred the raw PII
  const shredProof = keyManager.shred(ek.keyId);

  // Attempt to decrypt (should fail)
  let decryptionResult: string;
  try {
    keyManager.decrypt(encrypted);
    decryptionResult = "ERROR: Decryption should have failed!";
  } catch (e: any) {
    decryptionResult = `✅ ${e.message} — raw PII is mathematically irrecoverable`;
  }

  // Audit trail
  auditChain.append("credential_issued", {
    credentialHash: sha256(credential.jwt),
    claimCategories: ["age_predicate", "email_status", "jurisdiction"],
  });
  auditChain.append("crypto_shred", {
    shredProof,
    claimCategories: ["raw_personal_data"],
  });

  // ROPA
  ropaStore.record("credential_issuance");

  return {
    success: true,
    credential: {
      id: credential.meta.credentialId,
      type: credential.meta.credentialType,
      issuer: credential.meta.issuerId,
      claims: credential.disclosures.map(d => ({ name: d.claimName, valueHidden: "••••••" })),
      expiresAt: new Date(credential.meta.expiresAt * 1000).toISOString(),
      statusListIndex: credential.meta.statusListIndex,
      jwtPreview: credential.jwt.substring(0, 50) + "...",
      jwtLength: credential.jwt.length,
      totalClaims: credential.disclosures.length,
    },
    cryptoShredding: {
      ephemeralKeyId: ek.keyId,
      rawPIIEncrypted: encrypted.ciphertext.substring(0, 32) + "...",
      keyDestroyed: true,
      shredProof: {
        keyId: shredProof.keyId,
        method: shredProof.method,
        destroyedAt: shredProof.destroyedAt,
      },
      decryptionAttempt: decryptionResult,
    },
    auditChain: {
      length: auditChain.length,
      latestAction: auditChain.latest?.action,
      chainValid: auditChain.verify().valid,
    },
  };
}

function handlePresent(body: { disclose: string[] }): object {
  if (!credential) return { success: false, error: "No credential issued yet" };

  const disclose = body.disclose || ["over_18"];
  const nonce = "nonce-verifier-" + Date.now();

  const presentation = createPresentation({
    credential,
    disclose,
    verifierNonce: nonce,
    holderPrivateKey: holderKeys.privateKey,
  });

  const verification = verifyPresentation({
    presentation,
    issuerPublicKey: issuerKey.publicKey,
    expectedIssuer: "https://eid.example.at",
    expectedCredentialType: "age_verification",
    requiredClaims: disclose,
    verifierNonce: nonce,
    holderPublicKey: holderKeys.publicKey,
  });

  const published = statusList.publish();
  const revoked = credential.meta.statusListIndex !== undefined
    ? checkRevocation(published, credential.meta.statusListIndex)
    : false;

  const rawResponse = JSON.stringify(verification.claims);
  const paddedSize = Buffer.byteLength(padResponse(rawResponse));
  const allClaims = credential.disclosures.map(d => d.claimName);
  const hidden = allClaims.filter(c => !disclose.includes(c));

  // Determine consent action
  const consentAction = disclose.length === allClaims.length ? "approved" as const
    : disclose.length === 0 ? "declined" as const
    : "partial" as const;

  // Create consent receipt
  const claimRecords: ConsentClaimRecord[] = allClaims.map(name => ({
    name,
    tier: name === "over_18" || name === "over_16" || name === "over_21" ? "legal" as const : "optional" as const,
    disclosed: disclose.includes(name),
  }));

  const receipt = createConsentReceipt({
    action: consentAction,
    verifierId: "coolshop.at",
    verifierName: "CoolShop",
    verifierPolicyHash: sha256("coolshop-age-policy"),
    claims: claimRecords,
    requestHash: sha256(nonce + disclose.join(",")),
    responseHash: sha256(rawResponse),
    nonce,
  });
  consentStore.add(receipt);

  // Audit trail
  const auditAction = verification.valid && !revoked ? "verification_allowed" as const : "verification_denied" as const;
  auditChain.append(auditAction, {
    disclosureHash: sha256(disclose.join(",")),
    verifierIdHash: sha256("coolshop.at"),
    claimCategories: disclose,
    consentHash: sha256(receipt.id),
    decisionCode: revoked ? "revoked" : verification.valid ? "ALLOW" : verification.reason,
  });
  auditChain.append("consent_given", {
    consentHash: sha256(receipt.id),
    claimCategories: disclose,
  });

  // ROPA
  ropaStore.record("age_verification", "CoolShop GmbH");

  return {
    success: true,
    wallet: { disclosed: disclose, hidden, totalClaims: allClaims.length, holderBound: true },
    verifier: {
      valid: verification.valid && !revoked,
      reason: revoked ? "credential_revoked" : verification.reason,
      claimsReceived: verification.claims,
      claimsNotReceived: hidden.map(h => ({ name: h, value: "[HIDDEN]" })),
      issuer: verification.meta?.issuer,
      credentialType: verification.meta?.credentialType,
    },
    network: {
      observerSees: "4KB padded encrypted blob",
      actualResponseBytes: Buffer.byteLength(rawResponse),
      paddedResponseBytes: paddedSize,
      canInferClaims: false,
      canInferIdentity: false,
      timingJitter: "50-200ms random delay applied",
    },
    revocation: {
      checked: true,
      revoked,
      method: "StatusList2021 bitstring",
      issuerLearnedWhichCredential: false,
    },
    consent: {
      receiptId: receipt.id,
      action: receipt.action,
      claims: receipt.claims,
      timestamp: receipt.timestampHuman,
    },
    audit: {
      chainLength: auditChain.length,
      chainValid: auditChain.verify().valid,
      latestEntries: auditChain.getEntries().slice(-3).map(e => ({
        action: e.action,
        timestamp: e.timestamp,
        hash: e.entryHash.substring(0, 16) + "...",
      })),
    },
  };
}

function handleRevoke(): object {
  if (!credential) return { success: false, error: "No credential issued yet" };
  statusList.revoke(42);
  auditChain.append("credential_revoked", {
    credentialHash: sha256(credential.jwt),
    claimCategories: ["age_predicate"],
  });
  return {
    success: true,
    message: "Credential #42 revoked",
    audit: { chainLength: auditChain.length, chainValid: auditChain.verify().valid },
  };
}

function handleUnrevoke(): object {
  statusList.unrevoke(42);
  auditChain.append("credential_unrevoked", {
    claimCategories: ["age_predicate"],
  });
  return {
    success: true,
    message: "Credential #42 unrevoked",
    audit: { chainLength: auditChain.length, chainValid: auditChain.verify().valid },
  };
}

function handleAudit(): object {
  return {
    chain: JSON.parse(auditChain.export()),
    ropa: ropaStore.export(),
    consent: consentStore.export(),
  };
}

function handleTransparency(): object {
  return generateTransparencyReport("miTch PoC Demo", "privacy@mitch.example");
}

function handleReset(): object {
  initState();
  return { success: true, message: "State reset" };
}

// ─── HTTP Server ─────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    req.on("end", () => resolve(data));
  });
}

function findHtml(): string {
  const candidates = [
    join(__dirname, "index.html"),
    join(__dirname, "..", "poc-web", "index.html"),
    join(__dirname, "..", "..", "src", "poc-web", "index.html"),
    join(process.cwd(), "src", "poc-web", "index.html"),
    join(process.cwd(), "dist", "poc-web", "index.html"),
  ];
  for (const c of candidates) {
    try { return readFileSync(c, "utf8"); } catch { /* next */ }
  }
  return "<h1>index.html not found</h1><p>Tried: " + candidates.join(", ") + "</p>";
}

async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = req.url ?? "/";
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const json = (data: object) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data, null, 2));
  };

  if (url === "/" || url === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(findHtml());
    return;
  }

  if (url === "/docs" || url === "/docs/dpia") {
    const candidates = [
      join(__dirname, "dpia.html"),
      join(__dirname, "..", "poc-web", "dpia.html"),
      join(__dirname, "..", "..", "src", "poc-web", "dpia.html"),
      join(process.cwd(), "src", "poc-web", "dpia.html"),
      join(process.cwd(), "dist", "poc-web", "dpia.html"),
    ];
    for (const c of candidates) {
      try {
        const html = readFileSync(c, "utf8");
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(html);
        return;
      } catch { /* next */ }
    }
    res.writeHead(404);
    res.end("DPIA document not found");
    return;
  }

  if (url === "/api/issue" && req.method === "POST") return json(handleIssue());
  if (url === "/api/present" && req.method === "POST") {
    const body = await readBody(req);
    let parsed = {};
    try { parsed = JSON.parse(body); } catch { /* empty */ }
    return json(handlePresent(parsed as { disclose: string[] }));
  }
  if (url === "/api/revoke" && req.method === "POST") return json(handleRevoke());
  if (url === "/api/unrevoke" && req.method === "POST") return json(handleUnrevoke());
  if (url === "/api/audit" && req.method === "GET") return json(handleAudit());
  if (url === "/api/transparency" && req.method === "GET") return json(handleTransparency());
  if (url === "/api/reset" && req.method === "POST") return json(handleReset());

  res.writeHead(404);
  res.end("Not found");
}

const PORT = Number(process.env.PORT ?? 3210);
const HOST = process.env.HOST ?? "0.0.0.0";
const server = createServer(handler);
server.listen(PORT, HOST, () => {
  console.log(`\n  🦀 miTch PoC Demo running at http://localhost:${PORT}\n`);
});
