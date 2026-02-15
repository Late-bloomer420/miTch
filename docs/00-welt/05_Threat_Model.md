# Threat Model (Practical)

## Threats (top)
1. **Correlation & metadata deanonymization**
   - Logs, request patterns, timing, unique proof structures can enable tracking.

2. **Requester overreach**
   - RP requests more than necessary (“just send full паспорт/ID”).
   - “Consent” dark patterns.

3. **Replay & context swapping**
   - Reusing a proof for a different RP or later time.

4. **Verification endpoint abuse (DoS)**
   - Attackers flood verification to degrade service or force fail-open behavior.

5. **Policy bypass / ambiguity bugs**
   - Missing fields, schema drift, inconsistent gates.

6. **Supply chain & tool hallucination**
   - AI code changes delete controls, loosen checks, or invent security features.

## Required mitigations
- **Proof binding** to request hash/nonce + audience + expiry.
- **Strict schema validation** of requests + policy manifest; missing => deny.
- **Gate precedence**: hard safety gates run first (rate limit, schema, binding) before expensive crypto.
- **WORM logs** for verification receipts (no raw PII).
- **Rate limiting** per requester/service identity (fixed window acceptable for Phase 0).
- **Honesty checks**: remove any false TEE/attestation claims unless real.
- **Test harness with confusion matrix** when doing policy classification (TP/FP/TN/FN).

## Security posture clarity
- Separate: *software-only assurances* vs *hardware-backed assurances*.
- Quantify residual risk; do not claim “unhackable”.
