# 32 — Config Profile v0 (Safe Defaults)

Stand: 2026-02-11

## Purpose
Provide explicit runtime configuration with deny-biased defaults.

---

## Suggested config shape

```yaml
api:
  port: 8080
  maxBodyBytes: 262144

security:
  allowedAlgs:
    - EdDSA
  clockSkewSeconds: 90
  nonceTtlSeconds: 600
  rateLimit:
    windowSeconds: 60
    maxRequestsPerRequester: 10

policy:
  manifestVersion: v0
  failClosed: true

logging:
  level: info
  piiRedaction: strict
  includeStableIdentifiers: false

receipt:
  wormEnabled: true
  store: file
  path: ./data/receipts.log

privacy:
  retentionProfile: v0
  denyOnUnknownClassification: true
```

---

## Non-negotiable defaults
- `failClosed = true`
- `piiRedaction = strict`
- `includeStableIdentifiers = false`
- Unknown version/predicate/classification => deny

---

## Validation
- Config schema validation at startup
- Startup abort if critical security fields missing
- Effective config fingerprint logged (non-sensitive)
