# First paying use case — decision brief (#284)

Date: 2026-11-23
Status: PROPOSED. A recommendation for the decision owner, not a decision. Not buyer evidence.
Decision owner: repository owner (author of #284, assignee of #143).
Follow-up: first-mover options and EU legal variance in `FIRST_MOVER_OPTIONS_AND_EU_LEGAL_VARIANCE_2026-11-23.md`.
Sub-issues: #324 decision record · #325 Austria workflow/legal map · #326 baseline comparison · #327 market matrix · #328 interview focus.

Sources were read on 2026-11-23: miTch documents on `master`, issues #142, #143 and #284, and the EC age verification policy page. Points marked *verify* come from general knowledge and have no source yet.

## 1. Recommendation

**Park age/liquor-store as a commercial first use case. Keep it as the ADOPT-1 technical reference profile, and move its protocol layer toward partner/reuse.** The first paying hypothesis stays with #143: an independent request-governance and evidence layer, tested on DACH hotel pre-arrival/check-in. That hypothesis has no public evidence either. The next step is therefore evidence, not build.

| Option | Verdict | Main reason |
|---|---|---|
| Pursue age/liquor-store as the first paying case | Not recommended | The Commission's age verification solution already gives an over-18 yes/no proof without other data. It is built on the same EUDI specifications. miTch's privacy argument is therefore not a differentiator here. |
| Narrow (reference profile only) | Recommended | ADOPT-1 already defines it as a test vehicle for fail-closed verification and the bounded result contract. |
| Partner/reuse (official verifier for the protocol layer) | Recommended, check first (#326) | Takes API-03, API-04 and API-07 out of miTch's own maintenance. Licence, operation model and data flow are not yet checked. |
| Park as a business line | Recommended | `GTM_SPRINT_ROADMAP.md` already defers "a standalone age-verification business". The use-case landscape says an age-only verifier is unlikely to be defensible without distribution. |

Confidence: medium. It rests on public facts and repository documents, not on interviews.

**What would reverse it:** one qualified buyer with budget for an age workflow that the EU solution does not cover, confirmed under the G1 counting rules.

## 2. ADOPT-1 vs #143

The two decisions are compatible if ADOPT-1's age profile is read as an engineering test vehicle. They conflict as soon as engineering time on that profile is counted as commercial progress.

| | ADOPT-1.0 (2026-10-01) | #143 / GTM roadmap |
|---|---|---|
| Kind of decision | Technical: the first profile of the verifier kit the RP deploys | Commercial: category, buyer, first journey |
| Use case | Age/liquor-store, `age` claim | DACH hotel pre-arrival/check-in |
| Role of age verification | Reference flow for session, nonce, trust and fail-closed result | "Demonstration/policy recipe, not the core category" |
| Buyer named | None | IAM, privacy or EUDI owner; integrators as the channel |
| Evidence required | Tests and negative paths | G1: 20 interviews, ≥8 problem confirmations, ≥3 buyer signals |

Proposed rule: *Age verification is the technical reference profile for ADOPT-1. It is not the first commercial use case. Work on it counts toward the #142 waves, never toward G1/G2.*

## 3. Evidence status

No public buyer evidence exists for either use case. G1 (11 Oct 2026) is open without a published tally. G2 (22 Nov 2026) has passed with no public sign of a paid Readiness Sprint. Under the existing stop rule, a missed G1 or G2 stops broad product expansion. Missing public evidence does not prove that no private interviews took place.

| Type | Statement | Source |
|---|---|---|
| Fact | The active verifier path returns `{ eligible }` to the application, but the verifier itself receives the numeric age. Profile C (`age_over_18`, a flat SD-JWT) fixes this, but it is non-official and no official wallet issues it. | `docs/tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md` §2, §6a |
| Fact | Live mode now requires a signed status list (API-05c, fixed 2026-11-20). Without a `status` claim, revocation is still not checked (#293). | `docs/qa/API_AUDIT_STAGE0_REMEDIATION_2026-11-20.md`, #293 |
| Fact | miTch's active verifier cannot verify the official EU proof of age (`eu.europa.ec.av.1` is mdoc, carried over the DC API or OpenID4VP 1.0 with DCQL). The official reference verifier can, but it is not production software. | `docs/qa/AGE_VERIFIER_BASELINE_COMPARISON_2026-11-23.md` |
| Fact | The Commission's age verification solution was "feature ready" on 15 Apr 2026. Member States are asked to roll out age verification by the end of 2026. The Commission will publish lists of trusted proof-of-age providers. | [EC policy page](https://digital-strategy.ec.europa.eu/en/policies/eu-age-verification) |
| Fact | Regulated RPs must accept EUDI wallets by 24 Dec 2027. Austria had published no wallet launch date as of 5 Oct 2026. | `docs/05-business/CARRIER_AND_REVENUE_MODEL_PROPOSAL_2026-11-03.md` |
| Assumption | Hospitality buyers pay for governance and evidence rather than transport. | #143, untested |
| Assumption | "Users will not pay and verifiers will not integrate." | #284, untested |
| Gap | The market matrix that #284 names was not found on `master`. | #327 |

## 4. Workflow under test

Austria is proposed because of the founder ecosystem (Innsbruck, ID Austria). The age workflow is kept only as a comparison baseline.

| Dimension | Commercial candidate: hotel registration (T02) | Reference: online alcohol sale (C01) |
|---|---|---|
| Workflow | Guests register before arrival; the record is matched at check-in | Age check before an online spirits order ships |
| Legal driver | Guest register for **all** guests under MeldeG §10: filed within 24 h, kept 7 years, with travel-document data ([USP](https://www.usp.gv.at/themen/brancheninformationen/gastronomie-und-tourismus/gaesteverzeichnis.html); exact fields still need counsel review, #325) | Youth protection is state law: 16 for beer/wine, 18 for spirits (*verify* online-sale duties) |
| Buyer (budget) | PMS vendor product lead, or hotel group COO/IT lead | E-shop owner or shop-platform vendor |
| Operator | Front desk | Shop operations or delivery |
| Decision maker | Hotel group management, with privacy-officer sign-off | Shop owner |
| Incumbent | Paper or tablet form, passport inspection, data entry into the PMS | Self-declaration checkbox, an IDV vendor, or an ID check at delivery |
| Fallback | Manual form at the desk | The courier checks ID at the door |
| Wallet dependency | Austrian EUDI wallet with a PID | EU age verification app or an EUDI wallet |

Germany abolished the hotel registration form for German citizens from 1 Jan 2025 (Bürokratieentlastungsgesetz IV); foreign guests still register under §§29–30 BMG ([Haufe](https://www.haufe.de/recht/weitere-rechtsgebiete/wirtschaftsrecht/meldepflicht-in-beherbergungsstaetten_210_639508.html), secondary source). That weakens T02 in Germany. Austria's 7-year retention also cuts against minimisation: the benefit there is fewer typed and wrong fields, not less data stored.

## 5. Differentiation test

The job to test: *"Before we put a wallet request into production, prove to our privacy officer and auditor that it asks only for what the purpose needs. Keep proving it when rules, schemas or wallets change."* The existing verifier stack checks a presentation. It does not produce this approval record.

Measure: days from request design to privacy sign-off, fields collected per check, and re-review effort after a change. Budget and willingness to pay follow the G1 kit (questions 11–15).

Evidence that would disconfirm the offer:

- Privacy sign-off for wallet requests is already fast, or the integrator handles it at no visible cost.
- The PMS vendor or the official verifier already ships a purpose/claim configuration that buyers accept as evidence.
- Buyers describe the problem but name no budget owner, trigger or deadline.
- The legal guest-registration fields leave nothing to minimise.
- Integrators would rebuild the record in-house within days.

## 6. Go/no-go and pilot prerequisites

| Gate | Criterion | Status 2026-11-23 |
|---|---|---|
| Buyer | G1 thresholds met | Open, no public tally |
| Buyer | ≥1 qualified hotel or PMS signal in Austria with a named budget role | Unknown |
| Advantage | One metric beats the #326 baseline | First baseline in `docs/qa/AGE_VERIFIER_BASELINE_COMPARISON_2026-11-23.md`; no advantage measured |
| Wallet | Guests can use an Austrian EUDI wallet with a PID | No launch date as of 5 Oct 2026 |
| Technical | #288, #276 and #292 merged | Verify on `master` |
| Technical | Revocation is checked even without a `status` claim (#293); signed status lists are done (API-05c) | Open |
| Technical | Interop record against an official reference wallet | Not done |
| Legal | Counsel has confirmed the Austrian guest-register fields and retention | Not done |

No live pilot before G4 (31 Mar 2027).

**Issuer side (later, out of scope):** if T02 passes, a hotel-issued stay or access entitlement (the T02 "I version") could be issued through the VeriCred gateway. Do not start this before the buyer gate.
