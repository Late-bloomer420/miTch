# Age verifier baseline comparison — 2026-11-23 (#326)

**Tracks:** #326, a sub-task of #284. Decision context: [`05-business/FIRST_PAYING_USE_CASE_DECISION_BRIEF_2026-11-23.md`](../05-business/FIRST_PAYING_USE_CASE_DECISION_BRIEF_2026-11-23.md).
**miTch base:** `master` @ `b00eb14`.
**Runtime:** Node v22.23.5, pnpm 10.34.9, Docker 29.10.0, Linux cloud container (16 GB RAM).
**Official verifier:** `ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:latest`, which reported v0.12.0 at start, digest `sha256:b56390f2…a3a07f`.
**Method:** sourced desk research (URLs below, all read on 2026-11-23) plus local runs in one container.
**Not done:** a full verified presentation. No wallet holding an EU proof-of-age attestation was available, so no option reached "first verified session". The timings below stop earlier, and each says where.

This document is not a security PASS, a conformance claim or buyer evidence.

## 1. Result

1. **miTch cannot verify the official EU proof of age today.** The EU age verification profile is mdoc only (`eu.europa.ec.av.1`, `age_over_18`). It uses the Digital Credentials API by default and OpenID4VP 1.0 with DCQL as a fallback. miTch's active verifier path accepts only an SD-JWT profile, and DCQL/OpenID4VP 1.0 parity is open (API-07). `eu.europa.ec.av.1` appears in miTch only in tests and type contracts, not on the active path.
2. **The official reference verifier speaks this profile, but it is not production software.** It accepted a DCQL request for `eu.europa.ec.av.1` / `age_over_18` and produced a signed request object. Its README says: "We strongly recommend to not put this version of the software into production use." The age verification developer guide says the same of its own reference verifier and requires each RP to host its own.
3. **The registration certificate is required, but the verifier does not check scope, and that matches the law.** The official verifier refuses to create a request without a Wallet Relying Party Registration Certificate (`MissingRegistrationCertificate`, HTTP 400). It did not check that the requested credential and claims are covered by the certificate: an age-verification request went out under a certificate that lists only PID claims (§3, probe 1). **Correction, added the same day:** Implementing Regulation (EU) 2026/1730, which amends 2025/848, places the scope check on the wallet unit (recital 3). Under its Art. 8(2), wallets must inform the user when a request goes beyond the certificate. So this is the designed split of duties, not a verifier defect. What remains open is the RP side: nothing checks a request against the RP's own certificate *before* it is sent, so a mis-scoped request reaches users as a wallet warning. That is the one observation here that fits the #143 hypothesis. It comes from one version, not from a market finding. Source for 2026/1730: [ELI](https://eur-lex.europa.eu/eli/reg_impl/2026/1730/oj); the Spanish OJ text was read secondhand by a research agent, and the English text is still to be checked.
4. **IDV vendors are cheap per check.** Published list prices range from USD 0.10 for age estimation to USD 1.89 per document verification (§4). A wallet-based age check therefore cannot compete on per-check price alone. Its argument has to be data minimisation, recognition, or both.

Consequence for #284: the measurements support "narrow + partner/reuse" for age verification. The protocol layer for the EU profile already exists upstream. miTch would have to add mdoc plus DCQL just to reach parity.

## 2. Comparison on the same workflow (online over-18 check)

| | EU AV solution + its reference verifier | EUDI reference verifier endpoint | IDV vendors | miTch verifier-demo (profile C) |
|---|---|---|---|---|
| Credential | mdoc `eu.europa.ec.av.1`, `age_over_18` only; "SHALL NOT include any other attribute" | Any DCQL: mdoc and SD-JWT VC | ID document and selfie | Flat SD-JWT `age_over_18` (non-official) |
| Data reaching the RP | Yes/no only | What the DCQL query requests | Document data, image, liveness | `{ eligible, profile }` to the app |
| Official wallet that presents it | AV app (pilots: FR, DK, GR, IT, ES, CY, IE in 2026) and national wallets | EUDI reference wallets | No wallet needed | None |
| Protocol | DC API (ISO 18013-7 Annex C); OpenID4VP 1.0 + DCQL fallback | OpenID4VP 1.0, DCQL, `haip` profile, DC API | Vendor SDK | Repository OID4VP subset; 1.0/DCQL parity unproven (API-07) |
| Hosting | RP self-hosts; hosted instance "not a production service" | RP self-hosts; "not production" | SaaS | RP self-hosts; development software |
| Licence | Verifier UI and issuer Apache-2.0; Android app EUPL-1.2; verifier backend not checked | Apache-2.0 | Proprietary | Repository licence |
| Revocation | "Does not support revocation"; 3-month validity, single-use batches | Status list check, default on | Vendor-side | Signed status list required in live mode (API-05c fixed 2026-11-20); revocation without a `status` claim is not checked (#293) |
| Price to RP | No fee stated | Hosting cost only | USD 0.10–1.89 per check (§4) | Not defined |

## 3. Measurements (this container, 2026-11-23)

| Step | miTch verifier-demo | Official verifier endpoint |
|---|---|---|
| Fetch | `git clone --depth 1` | `docker pull` 8 s (image 599 MB) |
| Install | `pnpm install --frozen-lockfile` 5 s (pnpm store already warm from an earlier clone, so not a cold-start number) | — |
| Build | `pnpm build` 24 s (31 turbo tasks) | — |
| Configure | None for tests | Documented `docker/docker-compose.yaml` fails at start (missing `intendedUses`, NullPointerException). It needed the develop properties file and the compose keystore mounted: 4 attempts, about 10 minutes for an experienced operator |
| Start | Not started; tests only | Spring context up in 3.9 s |
| First request | 4 test files, 58 tests pass in 2 s (`age-over-18-profile`, `active-profile`, `connect-route`, `oid4vp-present`) | Signed age-verification request object (`request.jwt`) in 0.1 s |
| First verified presentation | Only with miTch's own mock issuer and wallet | Not reached: no wallet holding an AV attestation |

Not measured: lines of glue code an RP writes, components to operate in production, cost per 1,000 checks, and end-user drop-off. These need a real integration, not a test run.

### Probes against the official verifier (DCQL, `jar_mode=by_reference`)

| # | Request | Result |
|---|---|---|
| 1 | AV `age_over_18`, `intended_use_id=1` (certificate lists PID claims only) | Accepted; request object carries `verifier_info` with the certificate |
| 2 | PID `birth_date`, `intended_use_id=1` | Accepted |
| 3 | PID `age_over_18`, `intended_use_id=1` (claim not listed in the certificate) | Accepted |
| 4 | AV `age_over_18`, no intended use | Refused: `MissingRegistrationCertificate`, HTTP 400 |

The test certificate is the sample shipped in `application-develop.properties`. A production certificate could change nothing in this behaviour, because no scope check happened.

## 4. IDV vendor list prices (read 2026-11-23)

| Vendor | Product | Price | Source |
|---|---|---|---|
| Didit | Age Estimation (bundled with passive liveness) | USD 0.10 per check | [didit.me/pricing](https://didit.me/pricing) (states "pricing changed on November 1, 2026") |
| Didit | Full KYC bundle | USD 0.33 per check | same |
| Veriff | Essential / Plus / Premium | USD 0.80 / 1.39 / 1.89 per verification; USD 49 / 99 / 209 monthly minimum | [veriff.com/pricing](https://www.veriff.com/pricing) |
| Yoti | Age estimation | Pricing pages returned 404 | — |

Onfido/Entrust and IDnow were not checked.

## 5. Sources (read 2026-11-23)

- [ageverification.dev](https://ageverification.dev/): introduction, how it works, verifier developer guide, roadmap, technical specification and Annex A (AV profile)
- [EU age verification policy page](https://digital-strategy.ec.europa.eu/en/policies/eu-age-verification)
- [eudi-srv-verifier-endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint) (README, releases, `docker/docker-compose.yaml`, `application-develop.properties`)
- [eudi-web-verifier](https://github.com/eu-digital-identity-wallet/eudi-web-verifier)
- [av-web-verifier-ui](https://github.com/eu-digital-identity-wallet/av-web-verifier-ui), [av-srv-web-issuing-avw-py](https://github.com/eu-digital-identity-wallet/av-srv-web-issuing-avw-py), [av-app-android-wallet-ui](https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui)
- miTch: [`qa/API_AUDIT_STAGE0_REMEDIATION_2026-11-20.md`](API_AUDIT_STAGE0_REMEDIATION_2026-11-20.md), [`tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md`](../tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md)

## 6. Follow-ups

- Test whether a reference wallet rejects a request that falls outside its registration certificate. That decides whether finding 3 is a real gap or a deliberate wallet-side control.
- Read the AV verifier backend (licence, stack) and the Annex B ZKP profile.
- If age verification stays as a reference profile (#324), decide whether profile C moves to `eu.europa.ec.av.1` through the official verifier (reuse) or through miTch's own mdoc and DCQL work (build).
