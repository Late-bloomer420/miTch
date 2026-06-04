# B2B Business Case 03 — Supply Chain & Professional Credentials

Stand: 2026-05-23
Vertical: Manufacturing procurement · ESG/CSRD reporting · Contractor & professional licensing
Status: Concept (verifier-side integration via `@askmi/verifier-sdk`; in-person via `@askmi/mdoc`)

## 1) Positioning

miTch is **not** a supplier registry and **not** an auditor.

miTch is a **proof-mediation layer** between a supplier's (or worker's) credentials and a buyer's
procurement / site-access systems:

- Audit certificates, ESG attestations, and professional licenses are issued by **accredited
  bodies** (TÜV, DEKRA, BSI, chambers) and held by the supplier/worker.
- The buyer receives only the **predicate** it needs (`iso_27001_valid`, `last_audit_within_12m`,
  `forced_labour_screened`, `license_valid AND recognised_in=DE`) — not the underlying contracts,
  personnel files, or audit reports.
- Cross-border recognition, freshness, and revocation are enforced fail-closed; multi-year audit
  chains are anchored for non-repudiation (`@askmi/anchor-service`).

## 2) Problem

CSRD/ESRS, the CSDDD, CBAM, and the EU Forced Labour Regulation oblige large companies to collect
**auditable evidence** about their suppliers and sub-suppliers — and to keep it current across
years and jurisdictions. Today this means spreadsheets of PDF certificates, manual re-collection,
and personnel data (e.g. workers' license and ID details) flowing to every site operator. It is
slow, unverifiable, and a GDPR Art. 28 processor-liability problem for worker data.

## 3) Solution

For each supplier qualification or site-access event:

1. The buyer requests a predicate (`iso_27001_valid AND iso_14001_valid AND
last_audit_within_12m AND forced_labour_screened`), or for a worker
   `license_valid AND recognised_in=<country>`.
2. The holder's wallet (or an mdoc on a site-access card) presents a signed proof; the policy
   engine checks issuer accreditation, freshness, jurisdiction, and revocation fail-closed.
3. The buyer verifies via `@askmi/verifier-sdk` and stores a WORM receipt as CSRD/CSDDD evidence.
4. A lapsed audit or suspended license fails closed (`DENY_CREDENTIAL_TOO_OLD`,
   `DENY_CREDENTIAL_REVOKED`).

## 4) Why now

- **CSRD / ESRS:** in-scope companies report from FY2024/2025 — auditable supplier evidence is
  now mandatory, not optional.
- **CSDDD:** supply-chain due diligence with chain-of-evidence (transposition through 2026).
- **CBAM:** verified embedded-emissions data from suppliers.
- **EU Forced Labour Regulation:** verified labour-standard attestations.
- **Directive 2005/36/EC:** cross-border recognition of professional qualifications — a natural
  fit for jurisdiction-aware predicates.

## 5) ICP (Ideal Customer Profile)

- Large EU manufacturers / OEMs with multi-tier supplier bases and CSRD obligations.
- General contractors managing many sub-contractors and licensed trades on site.
- Primary buyer: **Head of Procurement / Supplier Risk**. Secondary: **CSRD Reporting Officer**.
  Tertiary: **Director of Operations** (site access).

## 6) MVP scope

- Supplier predicates: `iso_27001_valid`, `iso_14001_valid`, `last_audit_within_12m`,
  `no_sanctions_match`, `forced_labour_screened`.
- Worker predicate: `license_valid` + `recognised_in=<country>` (`@askmi/mdoc` for NFC tap).
- 1 accredited-auditor issuer + 1 buyer pilot.
- Anchored audit chain for multi-year non-repudiation.

## 7) Monetization options

- Per-verification pricing for supplier qualification checks.
- CSRD/CSDDD evidence-pack subscription (WORM receipts + anchored audit trail export).
- Site-access module: per-seat pricing for contractor/worker license verification.

## 8) KPI for pilot success

- Stale-audit suppliers blocked (target: 100%, `DENY_CREDENTIAL_TOO_OLD`).
- Non-accredited issuer attestations rejected (target: 100%, `DENY_UNTRUSTED_ISSUER`).
- Cross-border license recognition decided correctly (target: 100% vs. ground truth).
- Worker PII exposed at site access (target: 0 — only the license boolean).
- Procurement time-to-qualify reduced vs. PDF baseline.

## 9) Risk notes

- **"Suppliers won't adopt yet another standard."** Adoption is verifier-side and
  issuer-concentrated: a small number of accredited bodies (TÜV, DEKRA, BSI) issue the
  credentials for most of the supplier base, so the integration surface is thin.
- Issuer-accreditation trust list is the anchor; only accredited bodies may be trusted issuers.
- Worker-data flows must stay predicate-only to respect GDPR Art. 28 processor limits.

## 10) Messaging sentence (external)

"miTch turns supplier certificates and worker licenses into verifiable predicates — your CSRD
evidence pack is anchored and auditable, and a contractor's site-access check leaks no personnel
data."
