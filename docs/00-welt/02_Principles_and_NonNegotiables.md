# Principles & Non‑Negotiables (Binding)

## Invariants (must always hold)
1. **Edge‑First Decisions**
   - Authorization and identity decisions occur on the user device.
   - Servers may verify proofs, but must not decide based on hidden user profiles.

2. **Ephemerality by Default**
   - Personal data exists only transactionally.
   - Destruction of user keys == effective erasure.
   - No “helpful” server-side caches of personal data.

3. **Data Minimization by Construction**
   - Only process what is strictly necessary for the stated purpose.
   - Prefer derived proofs / predicates (“over 18”) over attributes (“DOB”).

4. **User as Root of Trust**
   - No silent delegation to providers.
   - No backdoors or recovery mechanisms that re-centralize power.

5. **Fail‑Closed Logic**
   - Ambiguity, mismatch, missing fields, unknown policy, or uncertainty => **DENY**.
   - “Proceed anyway” is not allowed.

## Automatic rejections (architectural anti-patterns)
- Centralized identity storage (any “master database of identities”).
- User profiling, behavioral analytics, or cross-service correlation.
- Blockchain dependency for core identity functions.
- Custody of financial assets / tokens / NFTs.
- “Trust us” models where guarantees are not mechanically enforced.

## EU framing (engineering implications)
- **GDPR**: purpose limitation, data minimization, storage limitation, integrity/confidentiality.
- **Proportionality**: requesters should not receive more than needed; policy must encode “least disclosure”.
- **Auditability without exposure**: log *proofs and decisions*, not identity records.
