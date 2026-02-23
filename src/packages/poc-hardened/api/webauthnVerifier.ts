import { createHmac, timingSafeEqual } from "crypto";

const webauthnTelemetry = {
  webauthn_native_attempt_total: 0,
  webauthn_native_success_total: 0,
  webauthn_native_deny_total: 0,
};

export interface WebAuthnEvidence {
  assertion: string;
  challenge: string;
  rpId: string;
  origin: string;
  issuedAt: string;
}

function b64u(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function verifySignedAssertion(e: WebAuthnEvidence, secret: string, context = "signed"): boolean {
  const payload = `${context}|${e.challenge}|${e.rpId}|${e.origin}|${e.issuedAt}`;
  const expected = b64u(createHmac("sha256", secret).update(payload).digest());

  try {
    const a = Buffer.from(e.assertion, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export function verifyWebauthnEvidence(e: WebAuthnEvidence): boolean {
  const mode = (process.env.WEBAUTHN_VERIFY_MODE ?? "allowlist").toLowerCase();

  if (mode === "native") {
    webauthnTelemetry.webauthn_native_attempt_total += 1;

    // native hook with bound adapter signature (challenge/rpId/origin/issuedAt)
    const secret = process.env.WEBAUTHN_NATIVE_ADAPTER_SECRET ?? "";
    if (!secret) {
      webauthnTelemetry.webauthn_native_deny_total += 1;
      return false;
    }

    const ok = verifySignedAssertion(e, secret, "native");
    if (ok) webauthnTelemetry.webauthn_native_success_total += 1;
    else webauthnTelemetry.webauthn_native_deny_total += 1;
    return ok;
  }

  if (mode === "signed") {
    const secret = process.env.WEBAUTHN_ASSERTION_HMAC_SECRET ?? "";
    if (!secret) return false;
    return verifySignedAssertion(e, secret, "signed");
  }

  const allowAssertions = (process.env.WEBAUTHN_ASSERTION_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return allowAssertions.includes(e.assertion);
}

export function getWebauthnTelemetry(): Record<string, number> {
  return { ...webauthnTelemetry };
}

export function resetWebauthnTelemetry(): void {
  webauthnTelemetry.webauthn_native_attempt_total = 0;
  webauthnTelemetry.webauthn_native_success_total = 0;
  webauthnTelemetry.webauthn_native_deny_total = 0;
}
