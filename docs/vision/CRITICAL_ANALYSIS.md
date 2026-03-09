# miTch Vision — Critical Analysis

> Not implementation-ready. Thinking space only.
> This document stress-tests the vision, finds gaps, and adds missing pieces.

---

## Revised Starting Point (important correction)

**We are NOT building an alternative to Apple/Google. We build ON TOP of them.**

Users are on iOS and Android. That is the user standard. We accept the platform as given.
The interoperability question (competing wallet vs infrastructure layer) resolves itself:
miTch works within the existing ecosystem, not against it.

The near-term focus is **visibility** — making data usage legible to the user:
- What is being read at this transaction?
- Who receives it?
- What is it used for?
- What was kept vs. what was forgotten?

The `PrivacyAuditService` already does this at the OS/browser/network layer (privacy score,
tracker detection, risk breakdown). The `ComplianceDashboard` shows the live proof boundary feed.
These are the seed of the right direction.

The task is not to build new infrastructure. It's to make the existing layer more visible,
more legible, and more useful for the user who doesn't have a computer science degree.

---

## What's Solid

- The forgetting layer is real, built, and the architecture is correct
- Three-layer separation (transaction / insight / ZK) is a coherent design
- EU regulatory environment is a genuine tailwind
- The platform/module direction is valid
- The power inversion concept (wallet negotiates on user's behalf) is the right framing

---

## Real Gaps and Weaknesses

### GAP 1 — Data Ingestion Is the Hardest Part (we glossed over it)

GDPR Art. 20 portability sounds clean. In practice:
- Banks produce PDFs or manual CSV exports
- Health systems routinely don't implement Art. 20 — non-compliance is common, enforcement is slow
- Social platforms give zip files requiring custom per-platform parsing
- Telecoms give complex XML that changes without notice

Building reliable automated connectors for each institution is a massive engineering AND political fight.
The local insight layer has no data to work with unless this is solved.

**Partial answer that doesn't require institutional cooperation:**
Start with data already on the device — Apple Health, banking app transaction patterns,
calendar/location data, app usage. Not as rich as full institutional data, but:
- Zero dependency on institutions cooperating
- Available from day one
- The EU Data Act (2024) creates a legal right to IoT/device-generated data — growing over time

**Realistic connector strategy:**
Build one connector per regulated category where Art. 20 is actually enforced
(banking: PSD2 forces open banking APIs in EU — this is actually workable today).
Don't try to build all connectors at once. One real one is worth ten theoretical ones.

---

### GAP 2 — ZK Framing Is Too Ambitious for Near-Term

"ZK circuits for arbitrary claims" = years away on mobile at usable performance.

But the actual use cases don't need general ZK:
- age >= 18
- income >= X
- A1c below threshold
- credit score in range Y–Z

These are **range proofs and simple predicates**. Bulletproofs do this today:
- Efficient range proofs
- No trusted setup ceremony
- Already deployed in Monero, Zcash, production systems

**Fix:** Reframe Layer 3 as "predicate proofs" not "general ZK."
Scope: prove a value is in a range without revealing the value.
That's achievable medium-term. Full ZK for complex computations stays long-term.

---

### GAP 3 — Revenue Model Has a Structural Tension

"Business verifier plugins — companies pay to be listed" creates incentive to grow the verifier network.
More verifiers = more sharing requests = structural pull toward MORE data sharing.
That's misaligned with the core privacy purpose.

**Better revenue candidates:**
- Users pay for premium utility features (insight automation, portability connectors)
  → revenue aligned with user value, not verifier growth
- Enterprise licensing: institutions run miTch as compliance middleware (B2B SaaS)
  → forgetting layer as a service for large verifiers who want to minimize data liability
  → doesn't involve the consumer wallet at all
  → higher-margin, no conflict with privacy mission

The enterprise B2B path (sell to institutions as compliance infrastructure) is structurally cleaner
and probably more capital-efficient early than a consumer marketplace.

---

### GAP 4 — Chicken-and-Egg Problem Not Addressed

Verifiers won't build plugins until users have wallets.
Users won't install wallets until verifiers accept them.
Standard two-sided marketplace cold start problem.

**Answer: acquire the verifier side first.**

Sell the forgetting layer to institutions as GDPR compliance middleware.
They hold less data → less liability → lower breach risk → regulatory preference.
That creates the first verifier network.
Consumer wallet adoption follows naturally.

Historical pattern: Stripe signed up businesses before users. Visa signed up banks before cardholders.
Supply side first, demand side follows.

**First wedge:** A single regulated sector where the compliance pain is highest.
Healthcare is obvious (EHDS, GDPR special categories for health data, breach costs).
Or financial services (DORA, PSD2, credit data regulations).

---

### GAP 5 — Module Security Model Is the Architectural Blocker

The open questions list mentions it, but it's actually the critical unbuilt piece.
A malicious "insight module" requesting transaction history could exfiltrate it.
The entire security model collapses if modules have raw credential access.

**Required design (before ecosystem is credible):**
- Modules declare required data types at install time (like app permissions)
- User approves each data type at install
- Modules receive computed summaries or typed fields through a wallet API
- Modules NEVER receive: raw credentials, private keys, full credential payloads
- Wallet is the gatekeeper — mediates all data access with logging

Reference problem: Chrome's extension ecosystem has had severe data theft from exactly this failure.
Learn from that before building.

---

## Missing Entirely

### MISSING 1 — The Identity Bridge

For the insight layer: the wallet needs to authenticate to institutions to request YOUR data.
That requires the institution to recognize you — which requires you to be authenticated to them.

Today's answer: re-enter your login credentials. Terrible UX, and gives credentials to the wallet.

Medium-term answer: eIDAS 2.0 EUDIW handles EU public services (2026+ rollout).
Private institutions are unsolved — no standard for "wallet authenticates to bank" exists yet.

**This is a missing layer between the credential wallet and external data sources.**
The vision needs to acknowledge this dependency and track the EUDIW rollout as an enabler.

---

### MISSING 2 — User Acquisition Strategy

Normal people don't install apps for privacy reasons.
Privacy is a feature, not a product, for most users.
The cold start mechanism isn't described.

**What's the first compelling use case that makes someone install the wallet
before any verifiers accept it?**

Candidates:
- Age verification (existing pain: you can't buy online without giving DOB to random retailers)
- Travel document management (boarding passes + ID in one wallet)
- Health data portability (Art. 20 access to your own records — if EHDS delivers this)
- Insurance claims (prove health status without giving full medical history)

The first use case needs to be one where the user gets value immediately,
WITHOUT needing the verifier side to have adopted miTch.
That probably means starting with a use case where YOU control both sides of the interaction
(e.g., sharing your health record with your own doctor — you and the doctor both choose to use it).

---

### MISSING 3 — Consent Receipt as a Portable Evidence Weapon

GDPR gives individuals rights to challenge, correct, and erase data.
Exercising these rights requires proving what you agreed to share and when.
Currently: institutions hold the consent records. You have to trust their logs.

**If your wallet holds signed consent receipts, you become the evidence holder.**
Show up to a GDPR complaint with your own cryptographically signed receipt.
Don't rely on the institution to have kept accurate records.

This flips the enforcement dynamic entirely.
This should be a core wallet feature, not a plugin — it's foundational to the rights layer.

**What a consent receipt contains:**
- Timestamp
- Verifier DID (who received the data)
- Claims shared (exactly which fields)
- Legal basis declared
- Signed by both wallet and verifier
- Hash-anchored for tamper evidence

The wallet accumulates these. The user has an immutable audit trail of their own data sharing.

---

### MISSING 4 — The Full Regulatory Tailwind

We mentioned GDPR Art. 20 and eIDAS 2.0. The picture is bigger:

| Regulation | What it enables for miTch |
|---|---|
| GDPR Art. 20 | Data portability from any processor — legal right to your data |
| eIDAS 2.0 / EUDIW | EU-wide digital identity wallet standard — miTch alignment mandatory by 2026 |
| Data Act (2024) | Right to data from connected devices (car, smart home, appliances) — zero institutional negotiation needed |
| AI Act | Transparency rights for automated decisions that profile you — the insight layer IS the transparency tool |
| EHDS (2025-2027) | Electronic access to health data across EU — mandatory for health systems |
| DORA | Financial institutions' digital resilience — forgetting layer reduces breach surface, maps to compliance |
| Data Governance Act | Data intermediaries as a regulated category — miTch could apply for DGA data intermediary status |

**Key insight:** These regulations are not just compliance burdens for others.
They are the legal crowbars that force institutions to give you your data.
The regulatory calendar is miTch's go-to-market calendar.

The Data Act in particular: IoT data portability is legally grounded from day one.
No institution cooperation needed — it's legally required.

---

### MISSING 5 — The Shadow Profile Problem (honest boundary)

Institutions hold data about you that you NEVER gave them. Inferred/derived data:
- Credit card company inferred your political views from spending patterns
- Insurer inferred health conditions from pharmacy purchase patterns
- Social platform inferred your sexuality from who you follow
- Employer background check company compiled data from dozens of sources you never interacted with

This inferred data:
- Is NOT covered by Art. 20 portability (proprietary inference, not data you provided)
- Is often the most powerful data institutions have on you
- Cannot be accessed, corrected, or challenged under current EU law

**This is the honest boundary of what miTch can address today.**
The AI Act's right to explanation for automated decisions chips at this, but narrowly.
Full access to inferred profiles requires new regulation that doesn't exist yet.

Acknowledging this boundary is important: it tells users what the wallet CAN and CANNOT do,
and it identifies the next advocacy frontier.

---

### MISSING 6 — Interoperability Positioning

miTch can't be the only wallet. EUDI wallet will exist (EU mandate). Apple Wallet is extending into ID.
Google Wallet. Various national eID implementations.

**Two possible positions:**

Option A: Competing wallet — miTch is a distinct app, users choose it over EUDI wallet.
Risk: EUDI wallet is mandated by law and pre-installed on phones. Hard to compete.

Option B: Interoperability layer — miTch works WITH any wallet. Focuses on the
forgetting layer, insight engine, and consent management as services that any wallet can use.
Advantage: doesn't need to win the wallet war. Becomes infrastructure rather than a product.

**This is an unresolved strategic choice that affects the whole architecture.**

---

## The EUDIW Situation (important constraint, 2026-03-09)

The EU Digital Identity Wallet (EUDIW) has real unresolved problems:

- **Unlinkability failure:** The Wallet Instance Attestation (WIA) creates a device identifier
  that can correlate a user across different verifiers — the opposite of its stated purpose
- **Large-scale pilot gaps:** The four EU pilots (POTENTIAL, EWC, DC4EU, NOBID) found real
  interoperability problems between member state implementations
- **Member state variance:** Some countries are well behind on timeline. The spec is still changing.
- **Trust model unclear:** Oversight mechanisms for wallet providers are underdefined.

**Conclusion: do not build a hard dependency on EUDIW.**
Design so EUDIW can slot in as the identity/auth layer later, when/if it stabilises.
Use what exists today. Don't wait for EUDIW to solve problems it hasn't solved yet.

---

## Summary: Resolution Status

| Question | Status | Answer |
|---|---|---|
| Interoperability positioning | ✅ RESOLVED | Build ON TOP of iOS/Android. Not competing with Apple/Google. |
| ZK scope | ✅ RESOLVED | Predicate proofs / range proofs (Bulletproofs). General ZK = long-term. |
| Revenue model tension | ✅ RESOLVED | Enterprise B2B licensing + user premium utility. Not verifier-pays. |
| Acquisition strategy | ✅ RESOLVED | Verifier side first. Healthcare or financial services as wedge sector. |
| UX overload at transaction time | ✅ RESOLVED | Minimal at transaction. Full detail in daily review. See UX_DAILY_REVIEW.md |
| Consent receipt as core feature | ✅ RESOLVED | Core wallet, not plugin. Portable, signed, exportable as evidence. |
| Escalation path | ✅ RESOLVED | Daily review → notification → DPA/lawyer/specialist directory. See UX_DAILY_REVIEW.md |
| Data ingestion strategy | ✅ RESOLVED | PSD2 open banking = first connector (EU banks have legal API obligation, OAuth2 auth, Nordigen/GoCardless free-tier aggregator). EHDS health data follows 2025–2027. Social media = skip for now. |
| Module security design | 🟡 PARTIAL | Working answer: capability declaration at install, typed API, no raw credential access. Full design needed before build. |
| Identity bridge / EUDIW dependency | ✅ RESOLVED | Do NOT depend on EUDIW. Use PSD2 OAuth2 today, national eIDs via OIDC for health. Design so EUDIW can replace the auth layer later without breaking the rest. |
| User acquisition cold start | ✅ RESOLVED | Two answers: (1) Daily review gives value on day one with zero verifier network — logs OS telemetry, app data access immediately. (2) Age verification at small local businesses is the network-effect wedge — business needs only a URL/QR on a tablet, no app install. |
| Shadow profile problem | ✅ RESOLVED (as boundary) | Inferred data is the honest limit of what's possible today. Partial lever: AI Act (2025+) requires explanations for high-risk automated decisions. miTch helps users request + store those explanations, building a picture from the output side. Full profile access requires new regulation that doesn't exist yet. |
| DPA directory maintenance | 🟡 PARTIAL | Links to official EU DPA register (edpb.europa.eu/about-edpb/board/members) — maintained by EDPB itself. National CERT/CSIRT links to ENISA directory. Low maintenance burden if pointing to authoritative sources. |

---

## What Remains Genuinely Open

- **Module security design:** Full sandbox architecture needs a proper design doc before any build starts.
- **AISP licence strategy:** Does miTch apply for its own licence or integrate with an existing aggregator (Nordigen)? Legal and cost implications differ significantly.
- **AI Act explanation requests:** What does the UX for requesting an AI Act explanation look like? How does miTch store it? This is a new feature category not yet in any existing component.
- **First verifier partnership:** Who is the first institution that runs miTch's forgetting layer as compliance middleware? Healthcare or banking? Which specific organisation?

---

## What We Should NOT Decide Yet

- Specific ZK circuit implementations (Bulletproofs variant, curve choice)
- Module API design (depends on module security design being done first)
- Any institutional partnership strategy (needs legal entity and business development capacity)
- Legal entity structure
- How to build the AISP integration specifically
