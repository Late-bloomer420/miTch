# 42 — Pilot-Critical Config

## Required for protected `/verify`
- `AUTH_TOKEN_REQUIRED=1`
- `AUTH_TOKEN=<strong-random-token>`

Optional for token rotation window:
- `AUTH_TOKEN_NEXT=<new-token-during-rollover>`

Clients must send:
- `Authorization: Bearer <token>`

## Runtime audience
- `RUNTIME_AUDIENCE=rp.example`

## Crypto agility baseline
- `ALLOWED_ALGS=EdDSA` (comma-separated allowlist)
- Keep this explicit so algorithm migrations are controlled and auditable.

## Key resolver for non-local mode
- `LOCAL_TEST_KEYS=0`
- `KEY_SOURCE_MODE=env|file|http`

### env mode
- `PUBLIC_KEYS_JSON={"kid-1":"-----BEGIN PUBLIC KEY-----..."}`

### file mode
- `KEY_SOURCE_FILE=./data/public-keys.json`

### http mode
- `KEY_SOURCE_URL=http://key-provider.local/keys`
- `KEY_SOURCE_URLS=https://resolver1.example/keys,https://resolver2.example/keys,https://resolver3.example/keys` (optional multi-source quorum)
- `KEY_SOURCE_QUORUM=2`
- `KEY_SOURCE_TIMEOUT_MS=1500`

Optional revoked lists:
- `REVOKED_KEY_IDS=kid-2,kid-3`
- `REVOKED_CREDENTIAL_IDS=cred-1,cred-2`

Credential status resolver mode:
- `CREDENTIAL_STATUS_MODE=env|http` (default: `env`)
- `CREDENTIAL_STATUS_URL=http://status-provider.local/credentials/revoked` (http mode)
- `CREDENTIAL_STATUS_TIMEOUT_MS=1500`
- `CREDENTIAL_STATUS_MAX_BYTES=65536` (fail-closed if status payload exceeds this)
- `CREDENTIAL_STATUS_REVOKED_CACHE_TTL_MS=10000` (revoked-only local cache TTL)
- `ALLOW_INSECURE_STATUS_URL=0` (keep default secure; set `1` only for controlled local testing)
- `CREDENTIAL_STATUS_REVOKED_CACHE_MAX_ENTRIES=1000`
- `REVOKED_STATUS_LIST_INDEXES=42,99` (env mode StatusList-style index deny list)

Operational behavior notes:
- missing/revoked/status-unavailable keys are deny-biased for high-risk purposes.
- keep key source timeout low (e.g., `KEY_SOURCE_TIMEOUT_MS=1500`) to avoid hanging verifier paths.

## Proof-fatigue baseline controls
- `PROOF_FATIGUE_WINDOW_SECONDS=3600`
- `PROOF_FATIGUE_MAX_HIGH_RISK_PROMPTS=5`
- `HIGH_RISK_PURPOSES=medical_record_access,account_recovery,kyc_full_profile`
- `SENSITIVE_CLAIMS=full_name,birth_date,address,national_id`

Optional strong re-auth scaffold (WebAuthn integration hook):
- `REQUIRE_STRONG_REAUTH=1`
- `WEBAUTHN_ASSERTION_ALLOWLIST=assertion-token-1,assertion-token-2`
- `WEBAUTHN_CHALLENGE_ALLOWLIST=challenge-1,challenge-2`
- `WEBAUTHN_RPID_ALLOWLIST=rp.example`
- `WEBAUTHN_ORIGIN_ALLOWLIST=https://rp.example`
- `WEBAUTHN_MAX_AGE_SECONDS=120`
- `WEBAUTHN_VERIFY_MODE=allowlist|signed|native` (default: `allowlist`)
- `WEBAUTHN_ASSERTION_HMAC_SECRET=<secret>` (required for `signed` mode)
- `WEBAUTHN_NATIVE_ADAPTER_SECRET=<secret>` (required for `native` mode in this scaffold)
- WebAuthn challenges are treated as one-time-use within the freshness window.
- request metadata should include:
  - `meta.reAuthMethod=webauthn`
  - `meta.reAuthAssertion`
  - `meta.reAuthChallenge`
  - `meta.reAuthIssuedAt` (ISO date-time)

## Jurisdiction compatibility (optional strict mode)
- `REQUIRE_JURISDICTION_MATCH=1`
- `RUNTIME_JURISDICTION=EU`
- requests should include `rp.jurisdiction` (e.g., `EU`) when strict mode is active.

## Cost KPI estimation inputs
- `ESTIMATED_COST_PER_VERIFICATION_EUR=0.002`
- `ESTIMATED_FIXED_MONTHLY_COST_EUR=0`
- `ESTIMATED_MONTHLY_VERIFICATION_VOLUME=10000`

## Safety defaults
- `NODE_ENV=production` to disable dashboard/test endpoints
- `ALLOW_METRICS=1` only if metrics endpoint is explicitly desired
- `MAX_BODY_BYTES=262144` (adjust if needed)
