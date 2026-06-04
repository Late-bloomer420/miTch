# Technical Trust Appendix for Verifiers

> **GTM-02** · Integration contract for relying parties · Date: 2026-05-25
> Status legend: ✅ implemented · 🟡 partial · 🔴 not implemented
> Authoritative status source: [`docs/compliance/EUDI_CIR_MATRIX.md`](../../compliance/EUDI_CIR_MATRIX.md)
> and [`STATE.md`](../../../STATE.md). Where this appendix and those files disagree, they win.

## 1. Supported protocols

| Area | Protocol / standard | Status | Notes / evidence |
|------|---------------------|--------|------------------|
| Presentation | OID4VP 1.0 (`vp_token`) | ✅ | `oid4vp`, `oid4vp-verifier` packages |
| Presentation def. | DIF Presentation Exchange v2 | ✅ | `oid4vp/src/presentation-definition.ts` |
| Self-issued | SIOPv2 (`id_token`, `sub_jwk`) | ✅ | `siopv2.ts` |
| Combined response | `vp_token` + `id_token` | 🟡 | Request parsed; full combined wallet response path not wired (CIR 2982-12) |
| Issuance | OID4VCI (`/credential`) | ✅ | `oid4vci`, `issuer-mock` |
| Issuance | Batch (`/batch_credential`) | 🔴 | Deferred post-MVP (CIR 2977-13) |
| Credential format | SD-JWT VC (`vc+sd-jwt`, `_sd_alg: sha-256`) | ✅ | `shared-crypto/sd-jwt-vc.ts` |
| Credential format | ISO/IEC 18013-5 mdoc / mDL | 🟡 | `@askmi/mdoc` codec + offline verify exist; wallet UI presentation path partial |
| Key binding | `kb+jwt`, `cnf.jwk` | ✅ | `createKeyBindingJWT` / `validateKeyBindingJWT` |
| Proof of possession | DPoP (RFC 9449) + `jti` replay + `ath` | ✅ | `dpop.ts` |
| Client auth | OAuth 2.0 Attestation-Based Client Auth | ✅ | `client-attestation.ts` |
| Verifier identity | Verifier Attestation JWT (`verifier_attestation`) | ✅ | `haip.ts` |
| Response security | HAIP `direct_post.jwt` + JWE `ECDH-ES+A256GCM` | ✅ | `haip.ts` encrypt/decrypt |
| Signatures | ECDSA P-256 (ES256); Brainpool P256r1/P384r1 | ✅ | `signing.ts`, `brainpool.ts` |
| Capability handshake | miTch Capability Negotiation v1 | ✅ | `docs/protocol/CAP_NEGOTIATION_V1.md` |
| Post-quantum | ML-DSA / ML-KEM crypto-agility | 🟡 | `pqc.ts` + `crypto-agility.ts`; negotiation registry, not default path |

## 2. Verifier obligations

A relying party integrating miTch **MUST**:

1. **Send a capability handshake** before proof exchange, with a semver `protocolVersion` and the v1
   capability flags. Security-critical flags are `layer0`, `revocation-online`, `replay-protection`.
2. **Supply a fresh, single-use `nonce`** per request and bind `state`. The wallet enforces nonce
   freshness (`nonce-store.ts`, TTL + single-use); a replayed nonce is rejected.
3. **Reject unsafe downgrades.** If both sides support a critical control and the requested profile
   disables it, the verifier MUST treat the result as `DENY` (downgrade protection).
4. **Encrypt the response** when using `direct_post.jwt` (`ECDH-ES+A256GCM`) and present a valid
   verifier attestation when operating under HAIP.
5. **Never request raw PII when a predicate suffices.** For the age use-case, request the
   *over-18 predicate*, not date of birth. miTch's `limit_disclosure=required` path is built for this.
6. **Check credential status** before acceptance. Status semantics are read from the `status` claim;
   note the live-fetch limitation in §4.
7. **Treat the proof as content-blind transport.** miTch does not vouch for the *truth* of issuer
   attributes — it mediates disclosure and enforces minimization. Trust-anchor selection of issuers
   remains the verifier's responsibility.

## 3. Failure behavior (fail-closed contract)

miTch resolves ambiguous or unsafe evaluations to **DENY** or **PROMPT** — **never** to a silent
ALLOW. The capability layer (`CAP_NEGOTIATION_V1`) maps failures to existing `DenyReasonCode` values:

| Condition | Result | Reason code |
|-----------|--------|-------------|
| Major protocol-version mismatch | DENY | `DENY_POLICY_UNSUPPORTED_VERSION` |
| Malformed version string | DENY | `DENY_POLICY_UNSUPPORTED_VERSION` |
| Missing security-critical capability | DENY | `DENY_POLICY_MISMATCH` |
| Unsafe downgrade attempt | DENY | `DENY_DOWNGRADE_ATTACK` |
| Ambiguous / missing policy parameters | DENY | (fail-closed default) |

For pilot v1, **all** capability mismatch classes resolve to `DENY`. This is verified in
`capability-negotiation.test.ts`. The broader fail-closed guarantee (no silent ALLOW) is enforced in
`policy-engine/src/engine.ts` and `allow-assertion.ts`.

## 4. Known limitations a verifier must plan around

These are `🟡`/`🔴` items from the CIR matrix that affect integration:

- **Live revocation fetch is not yet wired** (CIR 2982-14): the `status` claim is read, but a live
  Token Status List fetch endpoint is not deployed. Plan revocation freshness accordingly.
- **EUDI Trust List registration is pending** (CIR 2982-15): the verifier set is checked against a
  local `trustedVerifiers` set, not a live eIDAS-node trust list.
- **LoA High is software-only** (CIR 2981-1): no TEE/Secure Element or Common Criteria evaluation yet.
  Do not rely on miTch for assurance levels that require certified hardware binding.
- **Proximity / offline presentation** (ISO 18013-5) is partial: codec and offline verification exist;
  the wallet BLE/NFC/QR presentation path is not complete.

## 5. Compliance posture

Against the four CIRs, miTch reports **41/53 (77%) implemented, 10 partial, 3 missing** as of
2026-03-06. The full per-requirement breakdown — and the production-readiness gap list — is the
[compliance evidence index](03_COMPLIANCE_EVIDENCE_INDEX.md). Do not infer certification from this
score; see the [security sign-off](04_SECURITY_SIGNOFF.md).
