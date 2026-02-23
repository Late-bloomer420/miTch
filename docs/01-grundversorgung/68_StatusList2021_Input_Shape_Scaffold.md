# 68 — StatusList2021 Input Shape Scaffold

Stand: 2026-02-11

## Implemented
`proofBundle` now supports optional StatusList2021-style metadata:

```json
"credentialStatus": {
  "type": "StatusList2021Entry",
  "statusListCredential": "https://...",
  "statusListIndex": "12345"
}
```

## Scope
- Schema-level and type-level readiness added.
- Verifier/credential-status module now accepts the shape.
- Full bitstring/index revocation verification is still next step.

## Why
This keeps batches small while preparing safe migration from ID-list revocation to standards-aligned status list checks.
