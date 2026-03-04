/**
 * Metadata Minimization — Response padding, disclosure padding, timing jitter
 */

import { randomBytes } from "crypto";
import { SDJWTPresentation, Disclosure } from "./sdjwt";

// ─── Response Padding ────────────────────────────────────────────

/**
 * Pad a JSON response to a fixed size so observers can't infer content from size.
 */
export function padResponse(data: string, targetBytes: number = 4096): string {
  const current = Buffer.byteLength(data, "utf8");
  if (current >= targetBytes) return data;

  // Parse, add padding field, re-serialize
  try {
    const obj = JSON.parse(data);
    const remaining = targetBytes - current - 20; // account for `,"_pad":"..."` overhead
    if (remaining > 0) {
      obj._pad = randomBytes(Math.floor(remaining / 2)).toString("hex").slice(0, remaining);
    }
    return JSON.stringify(obj);
  } catch {
    // Not JSON — pad with whitespace
    return data + " ".repeat(targetBytes - current);
  }
}

// ─── Disclosure Padding ──────────────────────────────────────────

/**
 * Pad disclosures to a fixed count so verifier can't infer credential complexity.
 * Dummy disclosures are indistinguishable from real ones (random base64url strings).
 */
export function padDisclosures(real: Disclosure[], targetCount: number = 8): Disclosure[] {
  const padded = [...real];
  while (padded.length < targetCount) {
    const dummySalt = randomBytes(16).toString("base64url");
    const dummyEncoded = randomBytes(32).toString("base64url");
    const dummyHash = randomBytes(32).toString("base64url");
    padded.push({
      salt: dummySalt,
      claimName: `_pad_${padded.length}`,
      claimValue: true,
      encoded: dummyEncoded,
      hash: dummyHash,
    });
  }
  // Shuffle so real disclosures aren't always first
  return shuffle(padded);
}

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ─── Timing Jitter ───────────────────────────────────────────────

/**
 * Add random delay to prevent timing correlation.
 */
export function jitteredDelay(minMs: number = 50, maxMs: number = 200): Promise<void> {
  const delay = minMs + Math.floor(Math.random() * (maxMs - minMs));
  return new Promise(resolve => setTimeout(resolve, delay));
}

// ─── Presentation Minimization ───────────────────────────────────

/**
 * Strip unnecessary fields from a presentation before sending to verifier.
 */
export function minimizePresentation(presentation: SDJWTPresentation): {
  jwt: string;
  disclosures: string[];   // only encoded strings, not full Disclosure objects
  holderBinding?: string;
} {
  return {
    jwt: presentation.jwt,
    disclosures: presentation.disclosedItems.map(d => d.encoded),
    holderBinding: presentation.holderBinding,
  };
}

// ─── Identical Decline Response ──────────────────────────────────

/**
 * Produce an identical response whether user declined or credential is missing.
 * Verifier can't distinguish between the two.
 */
export function declineResponse(requestId: string): {
  requestId: string;
  decision: "DENY";
  decisionCode: "not_available";
  verifiedAt: string;
  _pad?: string;
} {
  const resp = {
    requestId,
    decision: "DENY" as const,
    decisionCode: "not_available" as const,
    verifiedAt: new Date().toISOString(),
  };
  // Pad to same size as successful response
  return JSON.parse(padResponse(JSON.stringify(resp)));
}
