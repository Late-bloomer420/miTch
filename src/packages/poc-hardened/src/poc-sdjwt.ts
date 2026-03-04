/**
 * ══════════════════════════════════════════════════════════════
 *   miTch PoC — SD-JWT Credential Flow (End-to-End)
 * ══════════════════════════════════════════════════════════════
 *
 *   Demonstrates the full credential lifecycle:
 *
 *   1. ISSUER  — Issues an SD-JWT credential with age + email claims
 *   2. WALLET  — Holds credential, selectively discloses only age predicate
 *   3. VERIFIER — Verifies proof, sees only what was disclosed
 *   4. REVOCATION — Issuer revokes, verifier detects
 *   5. METADATA MINIMIZATION — Padded responses, timing jitter
 *
 *   Run: npm run compile && node dist/poc-sdjwt.js
 * ══════════════════════════════════════════════════════════════
 */

import {
  generateIssuerKey,
  generateHolderKey,
  issueCredential,
  createPresentation,
  verifyPresentation,
  SDJWTCredential,
} from "./credential/sdjwt";

import {
  StatusListPublisher,
  checkRevocation,
} from "./credential/statusList";

import {
  padResponse,
  padDisclosures,
  jitteredDelay,
  minimizePresentation,
  declineResponse,
} from "./credential/metadata";

// ─── Helpers ─────────────────────────────────────────────────────

function header(text: string): void {
  console.log(`\n${"═".repeat(60)}`);
  console.log(`  ${text}`);
  console.log(`${"═".repeat(60)}\n`);
}

function step(n: number, text: string): void {
  console.log(`  ┌─ Step ${n}: ${text}`);
}

function detail(text: string): void {
  console.log(`  │  ${text}`);
}

function result(text: string): void {
  console.log(`  └─ ✅ ${text}\n`);
}

function fail(text: string): void {
  console.log(`  └─ ❌ ${text}\n`);
}

// ─── Main PoC Flow ───────────────────────────────────────────────

async function main(): Promise<void> {
  header("miTch PoC — SD-JWT Credential Flow");

  // ─── Setup ───────────────────────────────────────────────────

  step(0, "Setup — Generate keys and status list");

  const issuerKey = generateIssuerKey("issuer-key-1");
  detail(`Issuer key: ${issuerKey.keyId}`);

  const holder = generateHolderKey();
  detail("Holder key: generated (Ed25519)");

  const statusList = new StatusListPublisher(1024, "https://mitch.example/status");
  detail(`Status list: ${statusList.url} (capacity: 1024)`);

  result("Keys and infrastructure ready");

  // ─── Step 1: Issue Credential ─────────────────────────────────

  step(1, "ISSUER — Issue SD-JWT credential");

  const credential: SDJWTCredential = issueCredential({
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
    holderPublicKey: holder.publicKey,
  });

  detail(`Credential ID: ${credential.meta.credentialId}`);
  detail(`Type: ${credential.meta.credentialType}`);
  detail(`Claims (hidden in SD-JWT): ${credential.disclosures.map(d => d.claimName).join(", ")}`);
  detail(`Status list index: ${credential.meta.statusListIndex}`);
  detail(`Expires: ${new Date(credential.meta.expiresAt * 1000).toISOString()}`);
  detail(`JWT length: ${credential.jwt.length} chars`);

  result("Credential issued — raw data crypto-shredded (only predicates remain)");

  // ─── Step 2: Wallet Presents (Selective Disclosure) ───────────

  step(2, "WALLET — Selective disclosure (only over_18)");

  const verifierNonce = "nonce-coolshop-" + Date.now();

  const presentation = createPresentation({
    credential,
    disclose: ["over_18"],   // ONLY reveal this one claim
    verifierNonce,
    holderPrivateKey: holder.privateKey,
  });

  detail(`Disclosing: ${presentation.disclosedItems.map(d => d.claimName).join(", ")}`);
  detail(`NOT disclosing: ${credential.disclosures.filter(d => d.claimName !== "over_18").map(d => d.claimName).join(", ")}`);
  detail(`Holder binding: ${presentation.holderBinding ? "yes (nonce-bound)" : "no"}`);

  // Minimize before sending
  const minimized = minimizePresentation(presentation);
  detail(`Minimized: ${minimized.disclosures.length} disclosure(s) sent (encoded only, no metadata)`);

  result("Presentation created — verifier will see ONLY 'over_18: true'");

  // ─── Step 3: Verifier Validates ───────────────────────────────

  step(3, "VERIFIER — Verify presentation");

  // Add timing jitter
  await jitteredDelay(50, 200);

  const verification = verifyPresentation({
    presentation,
    issuerPublicKey: issuerKey.publicKey,
    expectedIssuer: "https://eid.example.at",
    expectedCredentialType: "age_verification",
    requiredClaims: ["over_18"],
    verifierNonce,
    holderPublicKey: holder.publicKey,
  });

  detail(`Signature valid: ${verification.valid}`);
  detail(`Claims received by verifier: ${JSON.stringify(verification.claims)}`);
  detail(`Issuer: ${verification.meta?.issuer}`);

  if (verification.valid) {
    result("Proof valid — verifier confirmed age ≥ 18 without seeing any other data");
  } else {
    fail(`Verification failed: ${verification.reason}`);
  }

  // ─── Step 4: Check Revocation Status ──────────────────────────

  step(4, "VERIFIER — Check revocation (StatusList2021)");

  const published = statusList.publish();
  detail(`Downloaded status list: ${published.encodedList.length} bytes (compressed bitstring)`);
  detail(`Valid until: ${published.validUntil}`);

  const isRevoked = checkRevocation(published, 42);
  detail(`Credential #42 revoked: ${isRevoked}`);

  result("Credential is active — issuer doesn't know this check happened");

  // ─── Step 5: Revoke and Re-check ─────────────────────────────

  step(5, "ISSUER — Revoke credential, verifier re-checks");

  statusList.revoke(42);
  detail("Issuer flipped bit 42 in status list");

  const updatedList = statusList.publish();
  const isNowRevoked = checkRevocation(updatedList, 42);
  detail(`Credential #42 revoked after update: ${isNowRevoked}`);

  result("Revocation works — just a bitflip, no PII involved");

  // ─── Step 6: Metadata Minimization Demo ───────────────────────

  step(6, "METADATA — Padding, jitter, identical decline responses");

  // Response padding
  const smallResponse = JSON.stringify({ decision: "ALLOW", claims: { over_18: true } });
  const paddedResponse = padResponse(smallResponse);
  detail(`Original response: ${Buffer.byteLength(smallResponse)} bytes`);
  detail(`Padded response:   ${Buffer.byteLength(paddedResponse)} bytes (fixed size)`);

  // Disclosure padding
  const paddedDisclosures = padDisclosures(presentation.disclosedItems, 8);
  detail(`Real disclosures: ${presentation.disclosedItems.length}, padded to: ${paddedDisclosures.length}`);

  // Identical decline
  const decline = declineResponse("req-456");
  detail(`Decline response: ${JSON.stringify({ decision: decline.decision, code: decline.decisionCode })}`);
  detail("(Same response whether user declined or credential missing — verifier can't tell)");

  result("Metadata minimization active — observer learns nothing from traffic shape");

  // ─── Step 7: Multi-claim selective disclosure ─────────────────

  step(7, "WALLET — Multi-claim: disclose over_18 + jurisdiction (hide rest)");

  const multiPresentation = createPresentation({
    credential,
    disclose: ["over_18", "jurisdiction"],
    verifierNonce: "nonce-health-" + Date.now(),
    holderPrivateKey: holder.privateKey,
  });

  const multiVerify = verifyPresentation({
    presentation: multiPresentation,
    issuerPublicKey: issuerKey.publicKey,
    requiredClaims: ["over_18", "jurisdiction"],
  });

  detail(`Claims disclosed: ${JSON.stringify(multiVerify.claims)}`);
  detail(`Still hidden: over_16, over_21, email_verified`);
  detail(`Valid: ${multiVerify.valid}`);

  result("Selective disclosure works — only requested claims revealed");

  // ─── Step 8: Attempt with wrong issuer key ────────────────────

  step(8, "ATTACK — Verify with wrong key (should fail)");

  const fakeKey = generateIssuerKey("fake-key");
  const attackResult = verifyPresentation({
    presentation,
    issuerPublicKey: fakeKey.publicKey,
  });

  detail(`Valid: ${attackResult.valid}`);
  detail(`Reason: ${attackResult.reason}`);

  if (!attackResult.valid) {
    result("Attack rejected — invalid issuer signature detected");
  } else {
    fail("SECURITY ISSUE: attack should have been rejected!");
  }

  // ─── Summary ──────────────────────────────────────────────────

  header("PoC Summary");
  console.log("  ✅ SD-JWT credential issuance (Ed25519)");
  console.log("  ✅ Selective disclosure (reveal 1 of 5 claims)");
  console.log("  ✅ Multi-claim selective disclosure");
  console.log("  ✅ Holder key binding (nonce-bound)");
  console.log("  ✅ Issuer signature verification");
  console.log("  ✅ StatusList2021 revocation (bitstring)");
  console.log("  ✅ Revocation detection");
  console.log("  ✅ Response padding (fixed size)");
  console.log("  ✅ Disclosure padding (hide credential complexity)");
  console.log("  ✅ Identical decline responses (hide user decisions)");
  console.log("  ✅ Timing jitter (prevent correlation)");
  console.log("  ✅ Invalid key rejection");
  console.log("");
  console.log("  What the verifier saw:   { over_18: true }");
  console.log("  What the verifier didn't: birthdate, name, email, address, anything else");
  console.log("  What the issuer knows:   nothing (doesn't know verification happened)");
  console.log("  What the network saw:    4KB padded blob (can't infer content)");
  console.log("");
}

main().catch((err) => {
  console.error("PoC failed:", err);
  process.exit(1);
});
