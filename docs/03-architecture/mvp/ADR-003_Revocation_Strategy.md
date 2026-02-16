# ADR-003 — Revocation Strategy (StatusList2021)

**Status:** ACCEPTED
**Date:** 2026-02-16
**Owner:** Privacy Engineering
**Decision:** Implement W3C StatusList2021 for privacy-preserving revocation

## Context

Credential revocation is required for:
- Compromised credentials (stolen keys)
- Expired identity documents (passport renewal)
- User-requested deletion (GDPR Art. 17)
- Issuer policy changes

**Privacy Concern:** Traditional OCSP creates correlation risk (verifier queries specific credential ID → issuer learns which verifier checked which user).

## Decision

**Strategy:** W3C StatusList2021 with bitstring encoding

**How it works:**
1. Issuer maintains bitstring (e.g., 1000000 bits = 125 KB)
2. Each credential gets assigned index (e.g., credential #5 → bit 5)
3. Verifier fetches entire list (not individual credential status)
4. Verifier checks bit at index locally
5. Result: Issuer doesn't know which credential was checked

**Privacy Properties:**
- ✅ No per-credential network requests
- ✅ Verifier anonymity (issuer sees list download, not credential check)
- ✅ Minimal correlation (many credentials share same list)
- ✅ Caching reduces network load

**Implementation:**
- Library: Custom implementation (lightweight)
- Encoding: Base64-compressed bitstring
- Cache: 60 minutes (configurable)
- Degraded mode: Fail-closed (allow credential if list unavailable)

## Alternatives Considered

### 1. OCSP (Online Certificate Status Protocol)
❌ **Rejected:** Privacy leak (issuer learns which verifier checks which credential)

### 2. CRL (Certificate Revocation List)
❌ **Rejected:** Large file size, poor scalability

### 3. Bloom Filters
⚠️ **Considered:** Good privacy, but false positives problematic

### 4. Accumulator-based (Cryptographic)
⚠️ **Future:** Better privacy, but complexity too high for MVP

## Consequences

### Positive
✅ W3C Standard compliance
✅ Privacy-preserving by design
✅ Good performance (cached list)
✅ Scalable (bitstring compression)

### Negative
⚠️ Issuer must host status list publicly
⚠️ Verifier must fetch list periodically
⚠️ Revocation not instant (cache delay)

### Mitigations
- Cache TTL short for critical use cases (5-15 minutes)
- Degraded mode: allow credential if list temporarily unavailable
- Monitoring: alert if list fetch rate anomalous

## Acceptance Evidence

- [x] StatusList2021 implementation working
- [ ] Privacy analysis: no per-credential leakage
- [ ] Performance: <100ms check with cached list
- [ ] Degraded mode tested (list unavailable)
- [ ] Cache eviction working correctly

## Security Considerations

**Threat:** Malicious issuer serves different lists to different verifiers
**Mitigation:** Content-addressed lists (hash in credential status URL)

**Threat:** Replay attack (old non-revoked list)
**Mitigation:** List includes issuance timestamp, verifier checks freshness

**Threat:** DoS on status list endpoint
**Mitigation:** CDN distribution, rate limiting

## Rollout Plan

**Phase 1 (MVP):** Mock status lists for testing
**Phase 2 (Pilot):** Real status lists with 10K capacity
**Phase 3 (Production):** Multiple lists with 1M+ capacity each

## References

- W3C StatusList2021: https://www.w3.org/TR/vc-status-list/
- Digital Bazaar Implementation: https://github.com/digitalbazaar/vc-status-list

## Change Log

- 2026-02-16: Initial decision (ACCEPTED)
- 2026-02-16: Implementation started (@mitch/revocation-statuslist)

## Next Steps

1. [x] Implement StatusListRevocationChecker package
2. [x] Add unit tests
3. [ ] Cross-browser integration tests
4. [ ] Performance benchmarking (<100ms verify)
5. [ ] Production deployment with CDN
