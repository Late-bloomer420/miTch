import { readFileSync, existsSync } from "fs";
import { getCredentialStatusCacheMetrics } from "../proof/credentialStatus";
import { getResolverTelemetry } from "../proof/httpKeySource";
import { getWebauthnTelemetry } from "./webauthnVerifier";

const EVENTS_PATH = "./data/events.jsonl";

interface ParsedEvent {
  eventType?: string;
  decision?: "ALLOW" | "DENY";
  decisionCode?: string;
  latencyMs?: number;
  details?: Record<string, string | number | boolean>;
}

function readEvents(): ParsedEvent[] {
  if (!existsSync(EVENTS_PATH)) return [];
  const raw = readFileSync(EVENTS_PATH, "utf8").trim();
  if (!raw) return [];
  return raw
    .split("\n")
    .map((line) => {
      try {
        return JSON.parse(line) as ParsedEvent;
      } catch {
        return {} as ParsedEvent;
      }
    })
    .filter((e) => Object.keys(e).length > 0);
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

export function getKpiSnapshot(): Record<string, number> {
  const events = readEvents();
  const decisions = events.filter((e) => e.eventType === "decision_made");
  const allows = decisions.filter((e) => e.decision === "ALLOW").length;
  const denies = decisions.filter((e) => e.decision === "DENY").length;
  const total = decisions.length;

  const adjudications = events.filter((e) => e.eventType === "adjudication_recorded");
  const falseDenies = adjudications.filter((e) => e.details?.outcome === "false_deny").length;
  const falseAllows = adjudications.filter((e) => e.details?.outcome === "false_allow").length;
  const legitAdjudications = adjudications.filter((e) => e.details?.outcome === "legit" || e.details?.outcome === "false_deny").length;

  const overrides = events.filter((e) => e.eventType === "decision_override").length;

  const replayDenies = decisions.filter((e) => e.decisionCode === "DENY_BINDING_NONCE_REPLAY").length;
  const replayAttempts = replayDenies;

  const denyCredentialRevoked = decisions.filter((e) => e.decisionCode === "DENY_CREDENTIAL_REVOKED").length;
  const denyStatusSourceUnavailable = decisions.filter((e) => e.decisionCode === "DENY_STATUS_SOURCE_UNAVAILABLE").length;
  const denyJurisdictionIncompatible = decisions.filter((e) => e.decisionCode === "DENY_JURISDICTION_INCOMPATIBLE").length;
  const denyReauthProofInvalid = decisions.filter((e) => e.decisionCode === "DENY_REAUTH_PROOF_INVALID").length;
  const denyResolverQuorumFailed = decisions.filter((e) => e.decisionCode === "DENY_RESOLVER_QUORUM_FAILED").length;

  const latencies = decisions
    .map((e) => e.latencyMs)
    .filter((v): v is number => typeof v === "number" && v >= 0);

  const cache = getCredentialStatusCacheMetrics();
  const resolver = getResolverTelemetry();
  const webauthn = getWebauthnTelemetry();

  const estimatedCostPerVerification = Number(process.env.ESTIMATED_COST_PER_VERIFICATION_EUR ?? 0.002);
  const allowedAlgsCount = (process.env.ALLOWED_ALGS ?? "EdDSA")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean).length;

  const reauthStrongEnabled = process.env.REQUIRE_STRONG_REAUTH === "1" ? 1 : 0;
  const webauthnMode = (process.env.WEBAUTHN_VERIFY_MODE ?? "allowlist").toLowerCase();
  const webauthnModeCode = webauthnMode === "native" ? 2 : webauthnMode === "signed" ? 1 : 0;
  const webauthnNativeModeEnabled = webauthnModeCode === 2 ? 1 : 0;
  const webauthnAllowlistModeEnabled = webauthnModeCode === 0 ? 1 : 0;
  const hasSignedSecret = (process.env.WEBAUTHN_ASSERTION_HMAC_SECRET ?? "").length > 0;
  const hasNativeSecret = (process.env.WEBAUTHN_NATIVE_ADAPTER_SECRET ?? "").length > 0;
  const webauthnSecretConfigValid =
    webauthnMode === "signed" ? (hasSignedSecret ? 1 : 0) : webauthnMode === "native" ? (hasNativeSecret ? 1 : 0) : 1;
  const estimatedFixedMonthlyCost = Number(process.env.ESTIMATED_FIXED_MONTHLY_COST_EUR ?? 0);
  const estimatedMonthlyVerificationVolume = Number(process.env.ESTIMATED_MONTHLY_VERIFICATION_VOLUME ?? total);
  const estimatedMonthlyRunCost =
    estimatedFixedMonthlyCost + estimatedCostPerVerification * Math.max(0, estimatedMonthlyVerificationVolume);

  // compact security posture score (0-100), deny-biased weighting
  let securityProfileScore = 100;
  if (falseAllows > 0) securityProfileScore -= 60;
  if (reauthStrongEnabled !== 1) securityProfileScore -= 10;
  if (webauthnModeCode === 0) securityProfileScore -= 10;
  if (webauthnSecretConfigValid !== 1 && webauthnModeCode > 0) securityProfileScore -= 20;
  if (denyResolverQuorumFailed > 0) securityProfileScore -= 10;
  if (denyStatusSourceUnavailable > 0) securityProfileScore -= 5;
  if (resolver.resolver_inconsistent_responses_total > 0) securityProfileScore -= 5;
  securityProfileScore = Math.max(0, Math.min(100, securityProfileScore));

  return {
    decisions_total: total,
    allow_total: allows,
    deny_total: denies,
    verification_success_rate: total > 0 ? allows / total : 0,
    replay_block_rate: replayAttempts > 0 ? replayDenies / replayAttempts : 1,
    false_deny_rate: legitAdjudications > 0 ? falseDenies / legitAdjudications : 0,
    false_allow_total: falseAllows,
    policy_override_rate: total > 0 ? overrides / total : 0,
    deny_credential_revoked_total: denyCredentialRevoked,
    deny_status_source_unavailable_total: denyStatusSourceUnavailable,
    deny_jurisdiction_incompatible_total: denyJurisdictionIncompatible,
    deny_reauth_proof_invalid_total: denyReauthProofInvalid,
    deny_resolver_quorum_failed_total: denyResolverQuorumFailed,
    deny_status_source_unavailable_rate: denies > 0 ? denyStatusSourceUnavailable / denies : 0,
    revoked_cache_hit_total: cache.revoked_cache_hit_total,
    revoked_cache_store_total: cache.revoked_cache_store_total,
    resolver_queries_total: resolver.resolver_queries_total,
    resolver_quorum_failures_total: resolver.resolver_quorum_failures_total,
    resolver_inconsistent_responses_total: resolver.resolver_inconsistent_responses_total,
    estimated_cost_per_verification_eur: estimatedCostPerVerification,
    crypto_allowed_algs_count: allowedAlgsCount,
    reauth_strong_enabled: reauthStrongEnabled,
    webauthn_verify_mode_code: webauthnModeCode,
    webauthn_native_mode_enabled: webauthnNativeModeEnabled,
    webauthn_allowlist_mode_enabled: webauthnAllowlistModeEnabled,
    webauthn_secret_config_valid: webauthnSecretConfigValid,
    webauthn_native_attempt_total: webauthn.webauthn_native_attempt_total,
    webauthn_native_success_total: webauthn.webauthn_native_success_total,
    webauthn_native_deny_total: webauthn.webauthn_native_deny_total,
    webauthn_native_success_rate:
      webauthn.webauthn_native_attempt_total > 0
        ? webauthn.webauthn_native_success_total / webauthn.webauthn_native_attempt_total
        : 0,
    estimated_monthly_verification_volume: Math.max(0, estimatedMonthlyVerificationVolume),
    estimated_fixed_monthly_cost_eur: estimatedFixedMonthlyCost,
    estimated_monthly_run_cost_eur: estimatedMonthlyRunCost,
    security_profile_score: securityProfileScore,
    latency_p50_ms: percentile(latencies, 50),
    latency_p95_ms: percentile(latencies, 95),
  };
}
