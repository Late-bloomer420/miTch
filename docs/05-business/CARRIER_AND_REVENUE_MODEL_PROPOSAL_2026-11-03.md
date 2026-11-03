# Carrier and Revenue Model — Proposal (AskMI)

Date: 2026-11-03
Status: PROPOSED — no decision taken yet. This is a governance proposal, not an accepted ADR.
Scope: legal carrier structure (Rechtsform/Träger) and revenue model for AskMI. Not product scope.

## Context (grounded in repo)

- `docs/vision/IDEAS.md` lists revenue ideas — Freemium/Pay-per-Use, Enterprise SLA/support,
  marketplace for third-party modules — with explicitly open questions: "Wer zahlt? Verifier
  oder Nutzer oder beide?" and "Open-Source-Core + Commercial API — Governance-Modell?".
- `docs/05-business/USE_CASE_LANDSCAPE_AND_SEQUENCED_ROADMAP_2026-09-11.md` defines commercial
  stop conditions and defers an AskMI-operated attestation network ("defer until demand/acceptance
  proven").
- Project guideline: the Privacy-Revocation-Authority stays a **separate, auditable role**. The
  repo contains **no** decision about a non-profit carrier (search for "gemeinnützig": 0 hits) —
  the carrier question is open.
- Repo-internal sources for an Innsbruck ecosystem mention Tilak GmbH (Tiroler
  Landeskrankenanstalten) and Tigewosi (`docs/vision/OUTREACH_INNSBRUCK.md`). A "Cunst&Co
  Innsbruck" is **not documented** in this repo and must be verified externally before relying
  on it as a supporter.

## Options

| Option | Structure | Consequence |
|---|---|---|
| A | Non-profit carrier (e. V. or gGmbH) holds OSS core, IP, brand + separate commercial GmbH for Enterprise SLA/support | Trust-neutral core + commercial arm; matches the "Open-Source-Core + Commercial API" idea (still open in repo) |
| B | Non-profit only (grants, donations, no commercial offering) | Maximum trust signal, but funding depends on grants/donations |
| C | Commercial only (GmbH/UG) | Full profit distribution possible, but no Gemeinnützigkeit status / tax benefits, weaker neutrality signal for the revocation-authority role |

## Legal cornerstones (general information, not legal advice)

- Gemeinnützigkeit requires Finanzamt recognition (§ 52 AO) and **Zweckbindung**: surpluses may
  be generated, but must be reinvested into the purpose; distribution to shareholders/members is
  prohibited. "Reinvest everything" is therefore **legally mandatory** for a non-profit, not an
  optional strategy.
- Personal profit withdrawal is incompatible with a non-profit form — if that is the goal,
  option C is the only fit.
- A non-profit may still pay salaries, commission audits/certifications and run infrastructure;
  it just may not distribute profits.

## Market context: documented figures from September/October 2026 surveys (sources below)

These are market indicators, **not financial projections** — the repo contains no revenue
forecasts, and none are invented here.

- **IDnow / Sapio Research, "EUDI Wallet Consumer Survey" (The Identity Gap)** — published
  **8 September 2026**, fieldwork June 2026, n=2,000 adults (Germany n=1,000, France n=1,000):
  40% cite better fraud protection as the most important factor for wallet use, **31% greater
  control over what data they disclose**, 29% transparency/tracking; 63% would use the EUDI
  Wallet more often if only the details a check needs could be shared. Direct relevance for
  AskMI's selective-disclosure positioning.
- **eID Easy EUDI Wallet status updates, September 2026 and October 2026** — per-member-state
  rollout categories (e.g., Croatia/Portugal/Liechtenstein moved to Category 4 in the September
  update).
- **didit.me country tracker, as of 5 October 2026** — Austria has **not published an EUDI
  Wallet launch date** as of that date; EU deadline: at least one wallet per member state by
  24 December 2026, mandatory acceptance by regulated relying parties by 24 December 2027.
- **Eudigo EUDI Index, as of 14 October 2026** — 25 of 27 countries checked against official
  sources.
- **Digital Austria (BKA/BMI/WKO) webinar, 17 September 2026** — ID Austria for businesses;
  documents the active Austrian ecosystem around ID Austria → EUDI Wallet.
- Context with earlier fieldwork dates (not Sep/Oct 2026, listed for completeness):
  Bitkom survey (Germany, n=1,004, fieldwork spring 2026): >50% had never heard of the EUDI
  Wallet, only ~20% know it, ~5% can explain it well. ID Austria user figures reported as 4.8
  million users (heute.at; article date not reliably determinable).

Interpretation (qualitative only): EUDI Wallet awareness/adoption is still low in autumn 2026,
while data-control is a top-3 user demand (31%). That supports a privacy-first wedge, but means
Pay-per-Use volume should be expected **late**, after wallet adoption grows; early revenue, if
any, is more plausible via grants and a small number of Enterprise/SLA contracts.

## Reinvestment logic (qualitative)

Under option A/B, reinvestment is legally required and typically goes to: independent audits and
certification, core team, legal/governance, and enterprise sales. Under option C, reinvestment is
a choice, not an obligation.

## Open points / next steps

1. Decide carrier option A/B/C — requires external legal/tax advice; not decidable from repo
   content alone.
2. Answer "Wer zahlt?" (verifier vs. holder) via the G1 interview kit
   (`docs/05-business/ASKMI_G1_INTERVIEW_KIT.md`).
3. Keep the Privacy-Revocation-Authority carrier question separate and auditable.
4. Verify any external supporter (e.g., "Cunst&Co Innsbruck") outside the repo before listing it.
5. No financial projections are made here; a first numeric model needs real assumptions
   (hourly rates, number of relying parties, license prices) that do not exist in the repo yet.

## Sources (accessed 2026-11-03)

- IDnow press release, EUDI Wallet Consumer Survey, Munich 8 September 2026:
  https://idnow.io/insights/pr/publishes-eudi-wallet-consumer-survey
- Survey summary (63% selective-sharing figure): https://air3.com/blog/eudi-wallet-consumer-survey-2026
- eID Easy status update September 2026: https://www.eideasy.com/blog/eu-digital-identity-wallets-september-2026
- eID Easy status update October 2026: https://www.eideasy.com/blog/eu-digital-identity-wallets-october-2026
- didit.me EUDI Wallet-by-country tracker (status 5 October 2026):
  https://didit.me/blog/eudi-wallet-launch-by-country/
- Eudigo EUDI Index (as of 14 October 2026): https://eudigo.eu/en/eudi-index/
- Digital Austria news, BKA/BMI/WKO webinar 17 September 2026:
  https://www.digitalaustria.gv.at/wissenswertes/news/news-102.html
- Bitkom EUDI-Wallet awareness survey (fieldwork spring 2026, n=1,004), via:
  https://www.heute.at/s/digitaler-ausweis-kommt-keiner-weiss-es-120185749 and
  https://www.egovernment.de/europas-digitale-brieftasche-hat-ein-bekanntheitsproblem-a-6424ce20417ac9aa8abc485defaa2e49/
- ID Austria user figures (4.8 Mio.): https://www.heute.at/s/digitale-ausweise-brechen-rekorde-was-2026-folgt-120150053
