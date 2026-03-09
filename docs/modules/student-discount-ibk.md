# Module Concept: Student Discount — Innsbruck
## "The Invisible Student" — Proof of Enrolment Without Identity Exposure

> Not implementation-ready. Concept and design only.
> Part of the Innsbruck Wedge strategy — see `docs/vision/OUTREACH_INNSBRUCK.md`

---

## The Problem

~35,000 students in Innsbruck (LFU, MCI, MUI TIROL, FHG) show their full student ID every
day to get discounts at the bus, cinema, gym, coffee shop, and software vendors.

A physical student ID exposes:
- Full name
- Date of birth
- Photo
- Matrikelnummer (student registration number)
- Faculty / field of study
- University affiliation

For a €1 discount on a coffee or a bus ticket.

**None of that information is needed to answer the actual question: "Is this person an active student?"**

---

## The miTch Answer

A single cryptographic predicate proof:

```
Is student: ✓
Status: active
Valid until: [session expiry]
Issued by: Universität Innsbruck / MCI / ID Austria
```

Name: not shared. Matrikelnummer: not shared. Date of birth: not shared. Faculty: not shared.

The vendor gets exactly what they need to grant the discount. Nothing more.
The student's wallet generates a new, unlinkable proof for every transaction.

---

## Data Sources (Ingestion)

Two parallel paths — both available in Austria today:

### Path A — ID Austria
Austria's national digital identity system is already in mass-market deployment in Tyrol.
ID Austria issues a signed attribute bundle that includes student status (via eAMS/BMI integration).

- Authentication: existing ID Austria app on student's phone
- Attribute: `Studierendenstatus` (active/inactive + expiry)
- Advantage: no university-specific integration needed; works across all Innsbruck institutions

### Path B — University OIDC / Shibboleth
Both Universität Innsbruck and MCI run identity federations based on Shibboleth/OIDC.
The student authenticates with their university credentials (same login as university portal).

- Authentication: university SSO (username + password, or MFA)
- Attribute: `eduPersonAffiliation: student` + `schacExpiryDate`
- Advantage: richer attributes (specific institution, faculty if needed for specialised proofs)

**miTch uses whichever source the student has available. The output proof is identical either way.**

---

## The Transformation — What the Module Does

The `student-discount-ibk` module runs inside the miTch sandbox.

It receives from the wallet core only:
- `identity.status` (active / inactive)
- `identity.expiry` (date)
- `identity.provider` (which institution issued it)

It never receives: name, Matrikelnummer, date of birth, address, photo, field of study.

The wallet core evaluates locally:

```
eligible = (status == "active") AND (expiry > today)
```

If eligible → wallet generates an ephemeral, single-use proof signed by the issuer's key.
If not eligible → wallet returns DENY. No data is shared.

---

## What the Vendor Receives

At the point of sale (QR code scan or NFC tap):

| Data field | Shared? | Why |
|---|---|---|
| `student_eligible: true` | ✅ Yes | Required for discount |
| `issuer: Universität Innsbruck` | ✅ Yes | Optional — vendor may require specific institution |
| `valid_until: [today 23:59]` | ✅ Yes | Proof expiry (prevents replay) |
| `proof_id: [random]` | ✅ Yes | Unlinkable per transaction — new ID every scan |
| Full name | ❌ No | Not needed for discount |
| Matrikelnummer | ❌ No | Not needed for discount |
| Date of birth | ❌ No | Not needed for discount |
| Field of study | ❌ No | Not needed for discount |
| Home address | ❌ No | Never |

---

## User Visibility — The Daily Review Entry

The student sees in their miTch daily review:

```
🟢 14:32 — Metropol Kino Innsbruck — Student Discount Verification
   ✓ Student status confirmed (LFU Innsbruck)
   ✗ Name: not shared
   ✗ Matrikelnummer: not shared
   ✗ Date of birth: not shared
   Session ended · Proof expired · No data retained
```

If a vendor requests more than student status:

```
🔴 20:15 — [Vendor Name] — Requested Matrikelnummer + Home Address
   ⚠ These fields are not required for student verification.
   Transaction blocked. This request has been flagged.
   → Mark this vendor as "overreaching"?
```

---

## The Collective Signal Mechanism

This is the mechanism that creates systemic change over time.

When a vendor requests data beyond what is needed for the stated purpose, the student can:
1. **Block the request** (miTch default: deny over-requesting)
2. **Mark the vendor as "overreaching"** — one tap

These flags are aggregated locally and (optionally, with explicit consent) contributed to a
shared signal layer. When 500+ students in Innsbruck mark the same vendor as overreaching:

- The vendor appears in the miTch "transparency feed" for other students
- Students can decide in advance whether to interact with that vendor
- Public pressure builds on the vendor to reduce their data requests
- Vendors who switch to minimal-disclosure get a "miTch Verified" indicator

This turns miTch into a collective data rights tool, not just an individual privacy tool.
The power of 35,000 students in one city is the wedge.

---

## Why This Works as the Innsbruck Wedge

### For students (demand side)
- Immediate, concrete value — save money without exposing identity
- No verifier network needed at start — student controls both sides if sharing with a friend,
  classmate, or any vendor who accepts a QR scan
- ID Austria is already on most Austrian students' phones — zero new infrastructure

### For vendors (supply side)
- **IVB (Innsbrucker Verkehrsbetriebe):** bus discount verification without storing Matrikelnummern
- **Kinos (Metropol, Cineplexx):** student pricing without ID copy liability
- **Local gastronomy:** fast verification, no staff training needed, just scan the QR
- **Software vendors / student rates:** remote verification without document upload
- **DSGVO argument:** "You hold no Matrikelnummern → zero breach liability for student data"

### For the city / institutions
- MCI and LFU reduce the surface area of student data flowing to third parties
- Tirol Datenschutzbeauftragter: demonstrates Art. 5(1)(c) data minimisation in practice
- Potential for Stadtmarketing Innsbruck to promote as "privacy-first student city"

---

## The FMA / Licensing Question

The student discount use case does **not** require an AISP licence.

The data source (ID Austria or university OIDC) is a direct authentication flow — the student
authenticates themselves, no third-party account access is involved. This is no different from
"login with university account."

An AISP licence (FMA, Austria) is only required if miTch pulls bank account data on the
student's behalf via PSD2 APIs (e.g. for the "rent covered" proof scenario).

**For the student discount case: no banking data, no licence needed. Start immediately.**

---

## Relationship to Other Vision Components

| Component | Role in this use case |
|---|---|
| Forgetting Layer (Layer 1) | Core: generates the minimal proof, destroys session data |
| Daily Review (Layer 2) | Shows the student their transaction log + any overreaching flags |
| Predicate Proofs (Layer 3) | The "is student" proof IS a predicate proof — proof of concept for the proof layer |
| ID Austria identity bridge | The concrete, live answer to the "identity bridge" open question for Austria |
| Collective Signal | New mechanism (not in other docs yet) — aggregated vendor flagging for systemic change |

---

## Open Questions for This Module

- Does ID Austria expose `Studierendenstatus` as a standalone attribute, or only via full
  identity presentation? Needs verification with BMF/BMI integration docs.
- University OIDC: does MCI's Shibboleth federation expose `eduPersonAffiliation` + expiry?
  Needs confirmation from MCI IT services.
- Vendor onboarding: what's the minimum a vendor needs to accept a miTch proof?
  (Answer: a URL or QR scanner — no app install required.)
- Collective signal: what's the privacy model for the aggregated flag data?
  Must not create a linkability risk. Threshold-based, no individual attribution.

---

## Next Step

Talk to MCI IT services about the Shibboleth/OIDC attribute set.
Talk to one local vendor (e.g. a campus coffee shop) about whether a QR-based "student: yes"
confirmation would work for their discount process.
That conversation is validation, not sales.
