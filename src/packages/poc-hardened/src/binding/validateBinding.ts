import { VerificationRequestV0 } from "../types/api";
import { DecisionCode } from "../types/decision";
import { isExpired } from "./expiryValidator";
import { computeRequestHash } from "./requestHash";
import { INonceStore } from "./nonceStore";

export interface BindingConfig {
  clockSkewSeconds: number;
  nonceTtlSeconds: number;
}

export interface BindingValidationResult {
  ok: boolean;
  code?: DecisionCode;
}

export async function validateBinding(
  request: VerificationRequestV0,
  runtimeAudience: string,
  nonceStore: INonceStore,
  config: BindingConfig
): Promise<BindingValidationResult> {
  if (request.rp.audience !== runtimeAudience) {
    return { ok: false, code: "DENY_BINDING_AUDIENCE_MISMATCH" };
  }

  if (isExpired(request.binding.expiresAt, new Date(), config.clockSkewSeconds)) {
    return { ok: false, code: "DENY_BINDING_EXPIRED" };
  }

  const computed = computeRequestHash(request);
  if (computed !== request.binding.requestHash) {
    return { ok: false, code: "DENY_BINDING_HASH_MISMATCH" };
  }

  const nonce = await nonceStore.consumeOnce(
    runtimeAudience,
    request.binding.nonce,
    config.nonceTtlSeconds
  );

  if (nonce === "replay") {
    return { ok: false, code: "DENY_BINDING_NONCE_REPLAY" };
  }

  return { ok: true };
}
