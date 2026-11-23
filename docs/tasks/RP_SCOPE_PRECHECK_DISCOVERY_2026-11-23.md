# RP-side registration-scope pre-check — discovery (#338)

Date: 2026-11-23
Status: DISCOVERY. No code and no decision. #338 is `needs-decision`. The missed-G1/G2 stop rule (#143) bars broad build, so this note defines what a spike would prove. It does not start one.
Related: #284, #326, #183 (wallet-side registered-attribute binding), #330 (EU legal variance), [interview kit variant B](../05-business/ASKMI_G1_INTERVIEW_KIT.md).

## 1. Problem in one sentence

A relying party (RP) can send a wallet request that goes beyond its own registration certificate. Today only the wallet notices, and it shows the user a warning. Nothing on the RP side catches the request before it is sent, and nothing records why an allowed request was allowed.

## 2. What is known

| Type | Statement | Source |
|---|---|---|
| Fact (observed) | The official verifier endpoint v0.12.0 requires a registration certificate, but sent an age-verification request under a certificate listing only PID claims, and a PID `age_over_18` request that was not listed either | [`qa/AGE_VERIFIER_BASELINE_COMPARISON_2026-11-23.md`](../qa/AGE_VERIFIER_BASELINE_COMPARISON_2026-11-23.md) §3 |
| Fact (secondary) | IR 2026/1730 assigns the scope check to the wallet unit and requires wallets to inform the user about requests beyond the certificate | #326 correction comment; English text not yet checked (#337) |
| Fact (observed) | The sample certificate shipped with the official verifier (`typ: rc-wrp+jwt`, ES256) lists allowed credentials in the **same shape as a DCQL query**: `format`, `meta` (`vct_values` / `doctype_value`) and `claim[].path`. It also carries `purpose[]`, `sub` (an LEI-style identifier), `entitlements`, `policy_id` (`0.4.0.19475.3.1`), `registry_uri`, `privacy_policy`, `supervisory_authority` and a `status` list reference | `application-develop.properties` of eudi-srv-verifier-endpoint, decoded 2026-11-23 |
| Fact (observed) | The sample uses a `null` path element (`["nationalities", null]`) to mean "every array element" | Same |
| Assumption | Production certificates follow ETSI TS 119 475 with the same `credentials` structure | Not verified against the standard text |

Consequence: a pre-send check is technically simple. It compares two structures of the same shape. The value, if there is any, lies in operation (change detection, evidence), not in algorithmic difficulty. That makes the interviews (#328, module D) more important than code.

## 3. Check semantics (proposal)

Input: one DCQL query, the RP's registration certificate, and optionally the intended-use id.

1. **Certificate validity first, fail-closed.** Signature, chain, status and expiry are checked by existing trust code. That overlaps with #183 and is not re-implemented here. An invalid, expired or revoked certificate means DENY.
2. **Credential match.** Each `credentials[]` entry of the query must match a certificate entry with the same `format` and an equal or narrower `meta` (`vct_values` ⊆, `doctype_value` =).
3. **Claim subset.** Each requested `claims[].path` must equal an allowed path. A certificate `null` element matches any index. A request `null` matches only a certificate `null`. A query with no `claims` means "the whole credential" and is DENY unless the certificate allows the whole credential, which needs to be checked in the standard.
4. **`claim_sets` and `credential_sets`.** Every option must be inside the scope, not just one of them. Otherwise a wallet can pick the out-of-scope option.
5. **Purpose.** The intended use the RP declares for this request must be one of the certificate's `purpose` entries. Free text cannot be checked automatically, so a mismatch is recorded, not inferred.
6. **Result.** ALLOW or DENY with reason codes (`CERT_INVALID`, `FORMAT_NOT_REGISTERED`, `CLAIM_NOT_REGISTERED`, `OPTION_OUT_OF_SCOPE`, `PURPOSE_UNMATCHED`). Never a single `ok: true`; see the ADOPT-1 result semantics.

## 4. Evidence record (proposal)

Fields follow the ADOPT-1 telemetry rules:
- the hash of the certificate, not its content;
- the hash of the request;
- the policy and software revision;
- requested and registered claim **names**;
- the result and reason codes;
- a timestamp.

The record holds no credential data, no user data and no stable person identifier. Retention is set per jurisdiction (#336).

## 5. Spike, if the owner decides "pursue" in #324 / #338

Scope: a pure function plus tests. No server, no UI and no new package before a decision.

Acceptance tests (all must fail on a naive "any certificate present" check):
- [ ] Probe 1 from #326 (AV request under a PID-only certificate) → DENY `FORMAT_NOT_REGISTERED`
- [ ] Probe 3 (PID `age_over_18`, not listed) → DENY `CLAIM_NOT_REGISTERED`
- [ ] Probe 2 (PID `birth_date`, listed) → ALLOW
- [ ] A `claim_sets` option outside the scope → DENY `OPTION_OUT_OF_SCOPE`
- [ ] A `null` array path: allowed when listed, DENY when the certificate lists only one index
- [ ] Expired or revoked certificate → DENY `CERT_INVALID`
- [ ] Evidence record contains no claim values (assertion over the serialised bytes)

Where it would live: next to the existing policy engine or verifier SDK. This needs an owner choice; API changes need explicit approval (CLAUDE.md).

## 6. Open questions

- The exact ETSI TS 119 475 profile and IR 2026/1730 Annex text in English: does a missing `claim` list mean "whole credential"? (#337)
- Do intermediaries (itsme, eID Easy, Lissi) already run such a check in their connectors? (#328, module D)
- Prior art: answered in §7.

## 7. Prior art: arXiv 2609.26220 (read 2026-11-23)

The paper is A. Sokolov (Tyche Institute), "Who Assures the Verifier? An Executable Assurance-Locus Audit of the European Digital Identity Wallet", v1, preprint v0.1, not peer reviewed, dated 2026-08-11. Its arXiv ID suggests September but the paper is dated August; the mismatch is not resolved. The artifact is published as arXiv ancillary files, and its licence is not stated.

It proposes:
- a 17-rule decision profile (`research-proposal-not-adopted`);
- a JSON Lines evidence receipt;
- 36 synthetic vectors, run through three study-authored implementations (108 runs, 0 disagreements);
- a source audit of the EC verifier, Multipaz and walt.id.

Its conclusion: existing artefacts "do not yet join governance, implementation and reliance evidence into one portable object". It says the proposal complements wallet certification, RP registration and FCAF, and does not replace any of them.

### Overlap with #338

| #338 step | Paper rule | Overlap |
|---|---|---|
| 1 Certificate validity | R_RP_UNREGISTERED, R_RP_SUSPENDED, R_RP_IDENTITY_MISMATCH | Same intent |
| 2–4 Credential match, claim subset, every option in scope | R_ATTRIBUTE_OVER_REQUEST ("requested attributes … subset of the registered attribute set") | Same intent, but the paper models it as a boolean fact |
| 5 Purpose | R_PURPOSE_MISMATCH | Same intent; neither defines how to match free-text purposes |
| Evidence record (§4) | Receipt (§4.4): profile and version, input hash, verdict and ordered reason codes, RP registration identifier, verifier and policy versions, time | Near-identical; §6.5 "prefer hashes, short-lived pseudonymous transaction references" matches our no-values rule |

**Conclusion: the core idea of #338 is not new.** Rules 2–6 plus the receipt are already published as a research profile, and it must be cited.

### What #338 adds (to be confirmed, not claimed)

- **Real objects instead of booleans.** The paper's inputs are "boolean or finite-state facts" (§4.5). It states that production cases "must use actual OpenID4VP, SD-JWT VC and mdoc objects" (§6.4). #338 evaluates real DCQL against the real registration certificate structure. That includes `claim_sets`, `credential_sets` and `null` array paths, none of which the readable text covers.
- **Runtime placement before sending.** The paper evaluates recorded transactions for conformance, audit and FCAF (the RP as system under test). #338 is a runtime gate on the RP side before the request leaves.
- **Observed evidence.** The paper's audit is "source-presence observations". #338 rests on runtime probes against the official verifier v0.12.0 (#326).
- **Change detection when certificates or schemas change.** The paper only names "declared retest triggers" (§6.4).

### What the paper has that #338 lacks

- Presentation-phase rules 7–14 (signature, disclosure binding, holder binding, audience, nonce, freshness, status, issuer trust). #338 leaves these to the verifier; the miTch path covers part of them (#326).
- Reliance-phase rules 15–17: `R_USE_EXCEEDS_APPROVAL`, `R_LAWFUL_BASIS_UNRECORDED`, `R_AUDIT_EVIDENCE_INCOMPLETE`. These fit miTch's evidence hypothesis and are worth adopting.
- A signed implementation and policy identity in the receipt (§6.4).

### Consequences

1. **Reuse the paper's reason codes** (`R_*`) instead of inventing new ones, and cite it. Our draft codes in §3 map onto them; one code that differs is `OPTION_OUT_OF_SCOPE`.
2. **Partner/reuse beats build.** The paper asks for an externally owned plugfest with real objects and mutation testing (§8). Contributing real-object vectors from #326 is a low-cost first step that gives external evidence. Reusing its code needs a licence first, because the artifact's licence is unknown.
3. **Add buyer risks to the interviews (module D).** The paper expects that "deployers may reject expensive receipts" and that "registrars may resist owning software assurance" (§8). Both are disconfirming signals.
4. **Consider the other buyer.** The paper's target owner is conformance and certification: FCAF, laboratories, supervisors. That is a different buyer from intermediaries and RPs, and #328 should test it.
