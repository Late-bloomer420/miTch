import { getKpiSnapshot } from "../api/kpi";

interface Thresholds {
  warnStatusUnavailableRate: number;
  critStatusUnavailableRate: number;
  warnResolverInconsistentTotal: number;
  critResolverInconsistentTotal: number;
  warnResolverQuorumFailuresTotal: number;
  critResolverQuorumFailuresTotal: number;
  warnDenyResolverQuorumFailedTotal: number;
  critDenyResolverQuorumFailedTotal: number;
  failOnWarning: boolean;
}

function getThresholds(): Thresholds {
  return {
    warnStatusUnavailableRate: Number(process.env.KPI_WARN_STATUS_UNAVAILABLE_RATE ?? 0.05),
    critStatusUnavailableRate: Number(process.env.KPI_CRIT_STATUS_UNAVAILABLE_RATE ?? 0.2),
    warnResolverInconsistentTotal: Number(process.env.KPI_WARN_RESOLVER_INCONSISTENT_TOTAL ?? 5),
    critResolverInconsistentTotal: Number(process.env.KPI_CRIT_RESOLVER_INCONSISTENT_TOTAL ?? 20),
    warnResolverQuorumFailuresTotal: Number(process.env.KPI_WARN_RESOLVER_QUORUM_FAILURES_TOTAL ?? 5),
    critResolverQuorumFailuresTotal: Number(process.env.KPI_CRIT_RESOLVER_QUORUM_FAILURES_TOTAL ?? 20),
    warnDenyResolverQuorumFailedTotal: Number(process.env.KPI_WARN_DENY_RESOLVER_QUORUM_FAILED_TOTAL ?? 2),
    critDenyResolverQuorumFailedTotal: Number(process.env.KPI_CRIT_DENY_RESOLVER_QUORUM_FAILED_TOTAL ?? 10),
    failOnWarning: process.env.KPI_FAIL_ON_WARNING === "1",
  };
}

function run(): void {
  const kpi = getKpiSnapshot();
  const t = getThresholds();

  const statusRate = Number(kpi.deny_status_source_unavailable_rate ?? 0);
  const cacheHits = Number(kpi.revoked_cache_hit_total ?? 0);
  const cacheStores = Number(kpi.revoked_cache_store_total ?? 0);
  const revokedTotal = Number(kpi.deny_credential_revoked_total ?? 0);
  const falseAllowTotal = Number(kpi.false_allow_total ?? 0);
  const reauthInvalidTotal = Number(kpi.deny_reauth_proof_invalid_total ?? 0);
  const denyResolverQuorumFailed = Number(kpi.deny_resolver_quorum_failed_total ?? 0);
  const resolverQuorumFailures = Number(kpi.resolver_quorum_failures_total ?? 0);
  const resolverInconsistent = Number(kpi.resolver_inconsistent_responses_total ?? 0);
  const estimatedCostPerVerification = Number(kpi.estimated_cost_per_verification_eur ?? 0);
  const cryptoAllowedAlgsCount = Number(kpi.crypto_allowed_algs_count ?? 0);
  const estimatedMonthlyRunCost = Number(kpi.estimated_monthly_run_cost_eur ?? 0);
  const securityProfileScore = Number(kpi.security_profile_score ?? 0);
  const reauthStrongEnabled = Number(kpi.reauth_strong_enabled ?? 0);
  const webauthnModeCode = Number(kpi.webauthn_verify_mode_code ?? 0);
  const webauthnNativeModeEnabled = Number(kpi.webauthn_native_mode_enabled ?? 0);
  const webauthnAllowlistModeEnabled = Number(kpi.webauthn_allowlist_mode_enabled ?? 0);
  const webauthnSecretConfigValid = Number(kpi.webauthn_secret_config_valid ?? 1);
  const webauthnNativeAttemptTotal = Number(kpi.webauthn_native_attempt_total ?? 0);
  const webauthnNativeSuccessTotal = Number(kpi.webauthn_native_success_total ?? 0);
  const webauthnNativeDenyTotal = Number(kpi.webauthn_native_deny_total ?? 0);
  const webauthnNativeSuccessRate = Number(kpi.webauthn_native_success_rate ?? 0);

  const issues: string[] = [];

  if (statusRate > t.critStatusUnavailableRate) {
    issues.push(`CRITICAL: deny_status_source_unavailable_rate=${statusRate} > ${t.critStatusUnavailableRate}`);
  } else if (statusRate > t.warnStatusUnavailableRate) {
    issues.push(`WARNING: deny_status_source_unavailable_rate=${statusRate} > ${t.warnStatusUnavailableRate}`);
  }

  if (cacheStores > 0 && cacheHits > cacheStores * 10) {
    issues.push(`WARNING: revoked cache hit/store skew high (${cacheHits}/${cacheStores})`);
  }

  if (falseAllowTotal > 0) {
    issues.push(`CRITICAL: false_allow_total=${falseAllowTotal} > 0`);
  }

  if (securityProfileScore < 60) {
    issues.push(`CRITICAL: security_profile_score=${securityProfileScore} < 60`);
  } else if (securityProfileScore < 80) {
    issues.push(`WARNING: security_profile_score=${securityProfileScore} < 80`);
  }

  if (reauthStrongEnabled === 1 && webauthnModeCode > 0 && webauthnSecretConfigValid === 0) {
    issues.push("CRITICAL: strong re-auth enabled but WebAuthn secret config is invalid");
  }

  if (webauthnNativeModeEnabled === 1 && reauthStrongEnabled !== 1) {
    issues.push("WARNING: WebAuthn native mode enabled while strong re-auth is not enabled");
  }

  if (reauthStrongEnabled === 1 && webauthnAllowlistModeEnabled === 1) {
    issues.push("WARNING: strong re-auth enabled but WebAuthn verify mode is still allowlist");
  }

  if (resolverInconsistent > t.critResolverInconsistentTotal) {
    issues.push(
      `CRITICAL: resolver_inconsistent_responses_total=${resolverInconsistent} > ${t.critResolverInconsistentTotal}`
    );
  } else if (resolverInconsistent > t.warnResolverInconsistentTotal) {
    issues.push(
      `WARNING: resolver_inconsistent_responses_total=${resolverInconsistent} > ${t.warnResolverInconsistentTotal}`
    );
  }

  if (resolverQuorumFailures > t.critResolverQuorumFailuresTotal) {
    issues.push(
      `CRITICAL: resolver_quorum_failures_total=${resolverQuorumFailures} > ${t.critResolverQuorumFailuresTotal}`
    );
  } else if (resolverQuorumFailures > t.warnResolverQuorumFailuresTotal) {
    issues.push(
      `WARNING: resolver_quorum_failures_total=${resolverQuorumFailures} > ${t.warnResolverQuorumFailuresTotal}`
    );
  }

  if (denyResolverQuorumFailed > t.critDenyResolverQuorumFailedTotal) {
    issues.push(
      `CRITICAL: deny_resolver_quorum_failed_total=${denyResolverQuorumFailed} > ${t.critDenyResolverQuorumFailedTotal}`
    );
  } else if (denyResolverQuorumFailed > t.warnDenyResolverQuorumFailedTotal) {
    issues.push(
      `WARNING: deny_resolver_quorum_failed_total=${denyResolverQuorumFailed} > ${t.warnDenyResolverQuorumFailedTotal}`
    );
  }

  const output = {
    checkedAt: new Date().toISOString(),
    thresholds: t,
    kpi: {
      deny_status_source_unavailable_rate: statusRate,
      revoked_cache_hit_total: cacheHits,
      revoked_cache_store_total: cacheStores,
      deny_credential_revoked_total: revokedTotal,
      false_allow_total: falseAllowTotal,
      deny_reauth_proof_invalid_total: reauthInvalidTotal,
      deny_resolver_quorum_failed_total: denyResolverQuorumFailed,
      resolver_quorum_failures_total: resolverQuorumFailures,
      resolver_inconsistent_responses_total: resolverInconsistent,
      estimated_cost_per_verification_eur: estimatedCostPerVerification,
      crypto_allowed_algs_count: cryptoAllowedAlgsCount,
      reauth_strong_enabled: reauthStrongEnabled,
      webauthn_verify_mode_code: webauthnModeCode,
      webauthn_native_mode_enabled: webauthnNativeModeEnabled,
      webauthn_allowlist_mode_enabled: webauthnAllowlistModeEnabled,
      webauthn_secret_config_valid: webauthnSecretConfigValid,
      webauthn_native_attempt_total: webauthnNativeAttemptTotal,
      webauthn_native_success_total: webauthnNativeSuccessTotal,
      webauthn_native_deny_total: webauthnNativeDenyTotal,
      webauthn_native_success_rate: webauthnNativeSuccessRate,
      estimated_monthly_run_cost_eur: estimatedMonthlyRunCost,
      security_profile_score: securityProfileScore,
    },
    issues,
    ok: issues.length === 0,
  };

  console.log(JSON.stringify(output, null, 2));

  if (issues.some((i) => i.startsWith("CRITICAL"))) {
    process.exitCode = 2;
    return;
  }

  if (issues.length > 0 && t.failOnWarning) {
    process.exitCode = 1;
  }
}

run();
