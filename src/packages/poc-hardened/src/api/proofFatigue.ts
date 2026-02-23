import { VerificationRequestV0 } from "../types/api";
import { hasStrongRecentReAuth } from "./reAuth";

const highRiskWindowHits = new Map<string, number[]>();

export interface ProofFatigueConfig {
  windowSeconds: number;
  maxHighRiskPromptsPerRequester: number;
  highRiskPurposes: string[];
  sensitiveClaimNames: string[];
}

const DEFAULT_HIGH_RISK_PURPOSES = ["medical_record_access", "account_recovery", "kyc_full_profile"];
const DEFAULT_SENSITIVE_CLAIMS = ["full_name", "birth_date", "address", "national_id"];

export function getProofFatigueConfig(): ProofFatigueConfig {
  const purposes = (process.env.HIGH_RISK_PURPOSES ?? DEFAULT_HIGH_RISK_PURPOSES.join(","))
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const claimNames = (process.env.SENSITIVE_CLAIMS ?? DEFAULT_SENSITIVE_CLAIMS.join(","))
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    windowSeconds: Number(process.env.PROOF_FATIGUE_WINDOW_SECONDS ?? 3600),
    maxHighRiskPromptsPerRequester: Number(process.env.PROOF_FATIGUE_MAX_HIGH_RISK_PROMPTS ?? 5),
    highRiskPurposes: purposes,
    sensitiveClaimNames: claimNames,
  };
}

function isHighRiskRequest(request: VerificationRequestV0, cfg: ProofFatigueConfig): boolean {
  if (cfg.highRiskPurposes.includes(request.purpose)) return true;
  return request.claims.some((c) => cfg.sensitiveClaimNames.includes(c.name));
}

export function checkProofFatigue(request: VerificationRequestV0, cfg: ProofFatigueConfig): {
  allowed: boolean;
  reason?: "DENY_REAUTH_REQUIRED" | "DENY_REAUTH_PROOF_INVALID";
} {
  if (!isHighRiskRequest(request, cfg)) {
    return { allowed: true };
  }

  // if caller indicates recent re-auth, validate evidence according to runtime mode
  const reAuth = hasStrongRecentReAuth(request.meta);
  if (reAuth.ok) {
    recordHighRiskPrompt(request.rp.id, cfg.windowSeconds);
    return { allowed: true };
  }

  const now = Date.now();
  const windowMs = cfg.windowSeconds * 1000;
  const arr = highRiskWindowHits.get(request.rp.id) ?? [];
  const kept = arr.filter((t) => now - t <= windowMs);

  if (kept.length >= cfg.maxHighRiskPromptsPerRequester) {
    highRiskWindowHits.set(request.rp.id, kept);
    return { allowed: false, reason: reAuth.invalidEvidence ? "DENY_REAUTH_PROOF_INVALID" : "DENY_REAUTH_REQUIRED" };
  }

  kept.push(now);
  highRiskWindowHits.set(request.rp.id, kept);
  return { allowed: true };
}

function recordHighRiskPrompt(requesterId: string, windowSeconds: number): void {
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const arr = highRiskWindowHits.get(requesterId) ?? [];
  const kept = arr.filter((t) => now - t <= windowMs);
  kept.push(now);
  highRiskWindowHits.set(requesterId, kept);
}

export function resetProofFatigue(): void {
  highRiskWindowHits.clear();
}
