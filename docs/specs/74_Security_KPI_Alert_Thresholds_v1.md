# 74 — Security KPI Alert Thresholds v1

Stand: 2026-02-11

## Purpose
Define simple, actionable alert thresholds for pilot operations.

## KPI signals and thresholds

### 0) Trust-break event (highest priority)
- Signal: `false_allow_total`
- Critical: `> 0` (zero-tolerance)
- Action:
  1. Immediate incident response (containment + root-cause)
  2. Notify pilot stakeholders and freeze risky rollout paths
  3. Add regression test before resuming normal operations

### 0b) WebAuthn strong-mode config invalid
- Signals:
  - `reauth_strong_enabled = 1`
  - `webauthn_verify_mode_code > 0`
  - `webauthn_secret_config_valid = 0`
- Critical: any occurrence
- Action:
  1. Fix missing/invalid WebAuthn secret config immediately
  2. Re-run `kpi:check` and verify critical clears

### 0c) Native mode posture mismatch
- Signal: `webauthn_native_mode_enabled = 1` with `reauth_strong_enabled != 1`
- Warning: any occurrence
- Action:
  1. Align native mode usage with strong re-auth policy
  2. Confirm this is intentional in runtime profile

### 0d) Strong mode with allowlist verifier drift
- Signal: `reauth_strong_enabled = 1` and `webauthn_allowlist_mode_enabled = 1`
- Warning: any occurrence
- Action:
  1. Move verification mode to `signed` or `native`
  2. Keep allowlist mode only for explicit compatibility windows

### 0e) Security profile score degradation
- Signal: `security_profile_score`
- Warning: `< 80`
- Critical: `< 60`
- Action:
  1. Investigate contributing penalties immediately
  2. Restore strong-mode and resolver health posture
  3. Pause risky rollout if critical threshold is breached

### 1) Status source degradation
- Signal: `deny_status_source_unavailable_rate`
- Warning: `> 0.05` over last review window
- Critical: `> 0.20` over last review window
- Action:
  1. Check status provider health/timeouts/content-type/payload size
  2. Validate network path and resolver reachability
  3. Keep fail-closed mode active until root cause confirmed

### 2) Revoked-cache dependency spike
- Signals:
  - `revoked_cache_hit_total`
  - `revoked_cache_store_total`
- Warning pattern: cache hits increase rapidly while status-source-unavailable denials also increase
- Critical pattern: sustained high cache-hit growth with unresolved provider instability
- Action:
  1. Treat as potential status backend incident
  2. Investigate stale-risk exposure window (TTL settings)
  3. Reduce TTL if needed and restore provider reliability

### 3) Revocation pressure change
- Signal: `deny_credential_revoked_total`
- Warning: sudden step-up versus recent baseline
- Action:
  1. Validate issuer/key incident feed
  2. Confirm revocation source integrity
  3. Inform pilot stakeholders if impact is broad

### 4) WebAuthn evidence drift
- Signal: `deny_reauth_proof_invalid_total`
- Warning: sustained increase over baseline
- Action:
  1. Check RP-ID/origin/challenge/age config alignment
  2. Validate strict-mode metadata generation in clients
  3. Review recent re-auth policy/config changes

### 5) Resolver inconsistency drift
- Signal: `resolver_inconsistent_responses_total`
- Warning: `> KPI_WARN_RESOLVER_INCONSISTENT_TOTAL` (default 5)
- Critical: `> KPI_CRIT_RESOLVER_INCONSISTENT_TOTAL` (default 20)
- Action:
  1. Verify resolver endpoint integrity and network path
  2. Check for targeted mismatch/eclipsing conditions
  3. Temporarily increase quorum strictness if needed

### 6) Resolver quorum failure drift
- Signal: `resolver_quorum_failures_total`
- Warning: `> KPI_WARN_RESOLVER_QUORUM_FAILURES_TOTAL` (default 5)
- Critical: `> KPI_CRIT_RESOLVER_QUORUM_FAILURES_TOTAL` (default 20)
- Action:
  1. Check resolver availability/latency and timeout settings
  2. Validate quorum configuration against endpoint quality
  3. Escalate if sustained failures impact verification continuity

### 7) Quorum-failure deny pressure
- Signal: `deny_resolver_quorum_failed_total`
- Warning: `> KPI_WARN_DENY_RESOLVER_QUORUM_FAILED_TOTAL` (default 2)
- Critical: `> KPI_CRIT_DENY_RESOLVER_QUORUM_FAILED_TOTAL` (default 10)
- Action:
  1. Investigate resolver disagreement vs outage root cause
  2. Confirm no targeted path manipulation
  3. Consider temporary stricter resolver profile and partner notification

## Operational notes
- Evaluate thresholds per rolling window (e.g., 15-60 min) rather than raw lifetime totals.
- `kpi:check` behavior can be tuned with `KPI_FAIL_ON_WARNING` (default soft-fail on warnings).
- These thresholds are pilot defaults and should be tuned with real traffic.
