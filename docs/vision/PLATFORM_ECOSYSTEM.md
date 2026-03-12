# miTch — Platform & Ecosystem Vision

> Not implementation-ready. Thinking space only.

---

## The Idea

miTch as a platform — not just a credential wallet, but a module ecosystem where developers
publish capability modules around data protection, insight, proof, and trust.

The core wallet stays open source and minimal.
The ecosystem compounds around it without growing the core attack surface.

---

## Distribution: EU Alternative App Marketplaces

The Digital Markets Act (March 2024) forces Apple to allow alternative app marketplaces in the EU.
AltStore PAL and Setapp Mobile are already live.

**Why this matters:**
- No App Store review gatekeeping — Apple cannot reject miTch for conflicting with their ad/data business
- Apple still notarizes for malware/security, cannot block on business grounds
- More permissive APIs: background processing, deeper WebAuthn integration, system-level crypto access
- Apple has structural incentive to block a privacy wallet that bypasses their ecosystem — DMA removes that veto

**Creating your own iOS marketplace:** Apple requires EU legal entity + €1M letter of credit.
Too high a barrier early. Use existing alternative marketplaces for distribution instead.

---

## The Plugin Ecosystem

An **in-app module registry** — a data-sovereignty app store living inside the wallet.
Not an iOS marketplace. Modules are downloaded into the wallet, run locally.

### Module Categories

**Data connectors**
Pull your data from institutions via GDPR Art. 20 portability rights.
Each connector targets a specific institution (bank, health system, telecom).
Data lands in the wallet. Never touches a third-party server.

**Insight modules**
Local-only dashboards — credit footprint, health risk, financial behavior.
Same model classes institutions use. Runs on device, no upload.
Reference population data sourced from published open datasets (WHO, ECB, etc.).

**Proof generators**
ZK circuits for specific claims — age bracket, income range, health status, EU residency.
Prove the conclusion without revealing raw data.
Reusable across all wallets once published.

**Consent auditors**
Full log: what you shared, with whom, when.
Revocation tools included.

**Verifier profiles**
Businesses publish their minimum disclosure requirements as a plugin.
User installs it → wallet pre-configures minimal disclosure automatically.
Wallet negotiates on the user's behalf — user never has to reason about what to share.

**Policy templates**
Pre-built disclosure rules for contexts — travel, healthcare, finance, government.

**Trust anchors**
Verify issuer DID chains, check revocation, validate credential provenance.

---

## The Power Inversion

**Current world:** verifiers demand data → users comply, often sharing more than necessary.

**With verifier profiles as plugins:** verifiers publish requirements → wallet knows in advance
exactly what's needed → presents minimum-viable proof automatically.

The wallet becomes the negotiation layer. The user's interests are represented by default.

---

## Network Effect

- Each data connector someone builds (bank X, health system Y) → more valuable for all users
- Each ZK circuit published for a proof type → reusable across all wallets
- Each verifier profile published → better UX for every user who interacts with that verifier
- Core stays minimal and secure. Ecosystem grows capability without growing attack surface.

---

## Revenue Model

| Stream | Who pays | What for |
|---|---|---|
| Core wallet | nobody | open source, always free |
| Business verifier plugins | companies (B2B) | listed as verified interaction partner, certified profile |
| Premium data connectors | users (subscription) | automated GDPR Art. 20 portability — the hard work of negotiating with specific institutions |
| Certified proof modules | regulated industries | audit-certified ZK circuits for insurance, healthcare, government — certification has commercial value |

**Key constraint:** revenue model must never create incentive to collect or retain user data.
B2B (verifiers paying) and certification fees are structurally safe.
User subscriptions for convenience features (automation) are acceptable.
Anything involving user data as a revenue input is not.

---

## Roadmap Horizon

| Horizon | What | Status |
|---|---|---|
| Now (build on current) | Daily review UX — transaction log, danger levels, notification, escalation path | Partially exists (audit-log package, PrivacyAuditService) |
| Now | Consent receipt as portable evidence — core wallet feature, not plugin | Partially implemented |
| Near term | Enterprise B2B: forgetting layer as compliance middleware for institutions | Verifier SDK implemented, ad-tech module exists |
| Near term | PSD2 open banking connector — first real data portability flow (EU banks already have APIs) | First real data connector |
| Medium term | In-app module registry — open API for developers to publish modules | Requires stable core + defined module API |
| Medium term | Predicate proof layer (Bulletproofs range proofs) for specific claim types | Narrowed from general ZK |
| Long term | Verifier profiles as standard interface for business data requirements | Requires ecosystem adoption |
| Long term | General ZK for complex computations | Research horizon |

**Note:** As of March 2026, the miTch repository contains 25 packages + 3 apps.

---

## Resolved Strategic Questions

**Interoperability positioning — RESOLVED**
We are not a competing wallet. We build ON TOP of iOS and Android.
Apple and Google are the platform. We accept that and build visibility on top of it.

**ZK scope — RESOLVED (narrowed)**
Not general ZK circuits. Scope = predicate proofs / range proofs only.
"Age >= 18", "income in range X–Z", "A1c below threshold."
Bulletproofs do this today, efficiently, no trusted setup. Already in production systems.
General ZK for complex computations stays long-term / research horizon.

**Revenue model tension — RESOLVED**
Verifier-pays creates incentive for more sharing. That's misaligned.
Cleaner paths:
- Users pay for premium utility (insight automation, portability connectors)
- Enterprise B2B licensing: institutions run miTch as compliance middleware (GDPR liability reduction)
- Certified proof modules for regulated industries (audit certification fees)

**Acquisition strategy — RESOLVED**
Verifier side first. Sell forgetting layer to institutions as GDPR compliance infrastructure.
They hold less data → less liability → lower breach risk.
First wedge sector: healthcare (EHDS mandate, GDPR special categories, high breach costs)
or financial services (PSD2 open banking already requires data portability APIs in EU).

---

## Open Questions (not answered yet)

- What does the module sandbox look like? Modules need to run locally but not access the core wallet's keys.
  → Working answer: modules declare data types at install, receive typed summaries via wallet API, never raw credentials or keys.
- How does module trust/verification work? Who audits a ZK circuit?
- Data ingestion in practice: PSD2 open banking (EU) is the first real connector — already has APIs.
  Non-banking institutions are harder; start with what's legally mandated.
- Does the Data Act (2024) IoT portability right create a faster path than Art. 20 for some connectors?
- What's the minimum viable daily review that ships as a first version?
