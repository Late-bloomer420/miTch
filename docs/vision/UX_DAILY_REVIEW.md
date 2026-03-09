# miTch — UX: Daily Review & Escalation Model

> Not implementation-ready. Thinking space only.

---

## Core Principle

The transaction moment is calm and minimal.
The information lives in the daily review — readable after the fact, when there's no pressure.

Users are not expected to be security experts at the moment of sharing.
They are expected to be curious humans who occasionally want to understand what happened.

---

## The Three Modes

### 1. At Transaction Time — Minimal

- FaceID first (authentication, separate moment, fast)
- Then: what leaves the wallet, what doesn't — one screen, one tap
- Small ambient indicator (green / amber / red) in the corner
- No tracker info, no score, no overload
- Silent if everything is clean

### 2. After the Day — Daily Review

A timestamped log of everything that happened today.
Like a bank statement, but for your data.

Each transaction entry shows:
- Who asked (verifier name + verified/unverified indicator)
- What was shared (fields disclosed)
- What was withheld (fields blocked)
- Danger level: 🟢 Clean / 🟡 Watch / 🔴 Danger
- What was forgotten (crypto-shred confirmed)

The user can:
- Scroll through, learn, build intuition over time
- Tap any entry for full detail (privacy score, tracker breakdown, what Google/Apple could observe)
- Ignore green entries entirely — they're just the record
- Act on amber/red entries

### 3. Proactive Notification — When Something Is Wrong

Not every transaction triggers a notification. Most don't.

Notification triggers:
- Unverified or unknown verifier requested data
- More data requested than the stated purpose justifies (data minimisation violation)
- Same verifier requested data multiple times in a short window
- A verifier you've shared with appears in a known breach database
- A transaction failed validation (credential tampered, revoked, expired)
- OS-level risk detected: new tracking SDK appeared in an app you used

Notification format:
- Short, plain language: "Rewe requested your home address today. That wasn't needed for age verification."
- Danger level clearly labeled
- One tap to see full detail
- One tap to take action

---

## The Escalation Path

This is the genuinely new part. Most privacy tools stop at "here's the risk."
miTch goes further: here's who you should talk to.

### Danger Level → Recommended Action

| Level | What it means | What miTch recommends |
|---|---|---|
| 🟢 Clean | Routine, verified, minimal disclosure | No action needed. Entry stays in your log. |
| 🟡 Watch | Unusual but not clearly wrong — more data than expected, unverified verifier, repeated requests | Review the entry. Consider whether you want to interact with this verifier again. |
| 🔴 Danger | Clear violation — data requested without legal basis, breach detected, credential manipulation | Notification sent. Action recommended. |
| 🔴🔴 Critical | Credential misuse, identity theft indicators, known bad actor | Immediate notification. Escalation to authorities recommended. |

### Escalation Options (shown in the app, user-initiated)

**File a GDPR complaint**
- Links to the relevant national Data Protection Authority (DPA) based on user's jurisdiction
- Pre-fills complaint details from the transaction log (what was shared, when, with whom)
- The consent receipt becomes evidence

**Consult a data protection lawyer**
- Curated directory of GDPR-specialist lawyers (EU-wide, filtered by country)
- Not a referral business — just a directory. miTch has no commercial interest in who the user picks.

**Contact a data security specialist**
- For technical incidents (credential manipulation, suspected identity fraud)
- Links to relevant national CERT/CSIRT organisations
- BSI (Germany), NCSC (UK), ENISA contacts for EU-level issues

**Export your evidence**
- Signed, exportable consent receipt package
- Cryptographic proof of what was shared, when, what was withheld
- Format usable as supporting evidence in a GDPR complaint or legal proceeding

---

## The Longitudinal Picture

Over time, the daily review accumulates into something more valuable:

- **Monthly summary:** How many verifiers saw you? What did they each receive? What was never shared?
- **Pattern detection:** "This is the 4th time this week Verifier X has requested your data."
- **Verifier reputation:** Based on your own history — clean, consistent, minimal vs. overreaching, repeated, unverified
- **Your data footprint:** A simple visual of what's known about you, by whom, over what period

This is the picture institutions have of you. For the first time, you have it too.

---

## Design Notes

**Silence is the primary signal.**
If the ambient indicator is green, the user learned something without reading anything.
Green means: verified issuer, minimal disclosure, clean session, everything forgotten. Trust confirmed.

**Danger should be rare and specific.**
If everything is red, red means nothing. Danger levels only work if most days are green.
The system must be honest — don't over-warn, don't under-warn.

**Plain language throughout.**
Not "VP token validated." Not "SD-JWT VC disclosed claims."
"Your age was confirmed. Your name was not shared."

**The log is permanent and portable.**
The user owns the log. It's stored locally. It can be exported.
It is never uploaded, never synced to miTch servers.
It is the user's evidence, not miTch's data.

---

## Open Questions

- What triggers the line between 🟡 Watch and 🔴 Danger? Needs calibration.
- How does the DPA directory stay current? Manual curation? Links to official EU register?
- Does the escalation path create legal liability for miTch if a recommendation is wrong?
- What's the minimum viable version of the daily review that ships first?
