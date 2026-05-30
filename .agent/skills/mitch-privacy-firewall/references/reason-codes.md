# Privacy Failure Categories

Use stable categories in review reports. Match exact repo deny codes where they already exist; use these as review-level categories when no exact code exists.

| Category                    | Meaning                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `FAIL_LOG_RAW_PII`          | Raw PII reaches logs, telemetry, analytics, console output, or debug artifacts.                  |
| `FAIL_STORE_RAW_PII`        | Raw PII is persisted without explicit basis and protection.                                      |
| `FAIL_NON_EPHEMERAL`        | A value that should be one-time or in-memory gains unbounded retention.                          |
| `FAIL_LINKABILITY_REUSE`    | A stable identifier, nonce, DID, or correlation vector is reused across contexts.                |
| `FAIL_LINKABILITY_NO_NONCE` | A request or presentation lacks replay-resistant nonce/challenge binding.                        |
| `FAIL_SEC_IMPLICIT_ALLOW`   | Missing, ambiguous, or exceptional state can lead to ALLOW.                                      |
| `FAIL_SEC_UNHANDLED_ERROR`  | Error handling can leak data, bypass checks, or produce partial success.                         |
| `FAIL_POLICY_MISMATCH`      | Decision metadata does not bind to the active PolicyManifest or conflicts with policy semantics. |
| `FAIL_AUTHORITY_UNKNOWN`    | Issuer, verifier, resolver, trust layer, or authority cannot be established.                     |
| `FAIL_INPUT_MISSING`        | Required input for a privacy/security decision is absent.                                        |
| `FAIL_SPEC_AMBIGUOUS`       | A spec leaves privacy, retention, custody, or legal basis ambiguous.                             |

When reporting implementation findings, cite the concrete project deny code if available, for example codes from `src/packages/policy-engine/src/deny-reason-codes.ts`.
