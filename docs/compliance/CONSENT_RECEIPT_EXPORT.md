# Consent Receipt Export Verification

Current export scope: OID4VP W-05 consent receipts only.

## Export structure

Each export contains:

- `exportedAt`
- `scope` (`filtered` or `full`)
- `filters` (`verifierQuery`, `timeframe`)
- `auditAnchorHash`
- `receiptSetHash`
- `exportHash`
- `count`
- `receipts[]`

Each receipt contains:

- `schemaVersion`
- `id`
- `verifier`
- `purpose`
- `claimsShared`
- `timestamp`
- `outcome`
- `decisionId`

## Verification steps

1. Parse the JSON export.
2. Confirm `scope` matches the intended export action.
3. Confirm `filters` match the UI state for the export.
4. Recompute the receipt-set canonical hash over `receipts`, `scope`, `filters`, and `auditAnchorHash`.
5. Compare the recomputed hash to `receiptSetHash`.
6. Recompute the export anchor hash over `scope`, `filters`, `auditAnchorHash`, and `receiptSetHash`.
7. Compare the recomputed hash to `exportHash`.

## Notes

- The export is metadata-only and does not contain raw PII.
- The export is not signed yet.
- The audit anchor is a lightweight binding to the current audit trail, not a full non-repudiation mechanism.
