# Social Login Privacy — Pseudonymous Platform Access

> **Status:** Spec Draft | **Priority:** Tier 2 (after Age Verification + Student Discount)
> **Regulation:** EU Digital Services Act (DSA), GDPR Art. 25, eIDAS 2.0
> **Market:** 4+ billion social media users globally

---

## Problem

Platforms increasingly require identity verification (DSA Art. 16a). Current solutions:

| Current Practice             | Privacy Impact                                            |
| ---------------------------- | --------------------------------------------------------- |
| "Login with Google/Facebook" | Shares name, email, photo, friends, location — everything |
| "Upload ID to Meta"          | Sends government ID copy to a private company             |
| Phone number verification    | Links real identity, enables cross-platform tracking      |

**Result:** Users must choose between platform access and privacy. There is no middle ground.

---

## miTch Solution: Pseudonymous Verified Login

miTch enables platform login that proves **what the platform legally needs** while sharing **nothing else**.

### What the Platform Gets

| Attribute         | Type                | Risk                                                     |
| ----------------- | ------------------- | -------------------------------------------------------- |
| `age_gte_18`      | Predicate (boolean) | 🟢 Low — no birthday, just threshold                     |
| `pseudonymous_id` | Pairwise DID        | 🟢 Low — unique per platform, unlinkable across services |
| `is_real_person`  | Predicate (boolean) | 🟢 Low — humanity proof via credential chain             |
| `eu_resident`     | Predicate (boolean) | 🟢 Low — jurisdiction only, no address                   |

### What the Platform Does NOT Get

| Blocked Attribute  | Risk Level      | Deny Reason                       |
| ------------------ | --------------- | --------------------------------- |
| `display_name`     | 🟡 Raw PII      | `DENY_PII_UNNECESSARY`            |
| `email`            | 🟡 Raw PII      | `DENY_PII_UNNECESSARY`            |
| `profile_photo`    | 🔴 Biometric    | `DENY_BIOMETRIC_BLOCKED`          |
| `friends_list`     | 🔴 Social Graph | `DENY_SOCIAL_GRAPH_BLOCKED`       |
| `location_history` | 🔴 Tracking     | `DENY_LOCATION_BLOCKED`           |
| `device_id`        | 🔴 Fingerprint  | `DENY_DEVICE_FINGERPRINT_BLOCKED` |

These are **structural blocks** — the Policy Engine denies them regardless of user consent. The data never leaves the wallet, not even encrypted.

---

## Architecture

### Flow

```
Platform (FlirtRadar, TikTok, etc.)
    │
    ├─ OID4VP Request: age, name, email, photo, friends, location, device_id
    │
    ▼
miTch Policy Engine
    │
    ├─ ALLOW: age_gte_18 (predicate)
    ├─ ALLOW: pseudonymous_id (pairwise DID, HKDF-derived)
    ├─ ALLOW: is_real_person (credential chain proof)
    ├─ ALLOW: eu_resident (jurisdiction predicate)
    │
    ├─ DENY: display_name      → DENY_PII_UNNECESSARY
    ├─ DENY: email              → DENY_PII_UNNECESSARY
    ├─ DENY: profile_photo      → DENY_BIOMETRIC_BLOCKED
    ├─ DENY: friends_list       → DENY_SOCIAL_GRAPH_BLOCKED
    ├─ DENY: location_history   → DENY_LOCATION_BLOCKED
    ├─ DENY: device_id          → DENY_DEVICE_FINGERPRINT_BLOCKED
    │
    ▼
Platform receives: { age_gte_18: true, pseudonymous_id: "pw-...", is_real_person: true, eu_resident: true }
```

### Pseudonymous ID (Pairwise DID)

- Generated via HKDF from user master key + platform DID
- **Unique per platform** — FlirtRadar and TikTok get different IDs
- **Stable per platform** — same user gets same ID on repeat login (session continuity)
- **Unlinkable** — no way to correlate IDs across platforms
- Implementation: `@mitch/shared-crypto` → `derivePairwiseDID()`

### Overreaching Detection

When a platform requests attributes beyond what's necessary for login:

1. **Per-attribute risk scoring:**
   - 🟢 Predicates (age, residency) → Low risk
   - 🟡 Raw PII (name, email) → Medium risk, blocked by default
   - 🔴 Biometric/Social/Location → High risk, structurally blocked

2. **Inference warning:** "With age + region + login time, the platform could narrow down your approximate profile → Risk: 🟡 Medium"

3. **Collective Signal:** Users can flag platforms as "overreaching" with one tap. When enough users flag the same platform (threshold: configurable, e.g. 500), the system:
   - Adds the platform to a public transparency feed
   - Auto-generates a DSA complaint template
   - No individual attribution — flags are aggregated anonymously

---

## Comparison: miTch vs. Current Login Methods

| Attribute               | Login with Google     | Login with Apple | miTch                       |
| ----------------------- | --------------------- | ---------------- | --------------------------- |
| Real name               | ✅ Shared             | ✅ Shared        | ❌ Blocked                  |
| Email                   | ✅ Shared             | ⚠️ Relay option  | ❌ Blocked                  |
| Profile photo           | ✅ Shared             | ❌ Not shared    | ❌ Blocked                  |
| Friends/contacts        | ⚠️ API access         | ❌ Not shared    | ❌ Structurally blocked     |
| Location                | ⚠️ Via Google account | ❌ Not shared    | ❌ Structurally blocked     |
| Device fingerprint      | ✅ Shared             | ⚠️ Limited       | ❌ Blocked                  |
| Age verified            | ❌ Not verified       | ❌ Not verified  | ✅ Cryptographic proof      |
| Cross-platform tracking | ✅ Same Google ID     | ⚠️ Possible      | ❌ Pairwise IDs, unlinkable |
| Humanity proof          | ❌                    | ❌               | ✅ Credential chain         |

**Key differentiator:** Apple's "Hide My Email" is a step forward but still shares a relay address. miTch shares **no contact information at all** — the platform gets a pseudonymous ID and verified predicates, nothing more.

---

## DSA Compliance Argument

The EU Digital Services Act (2024) requires platforms to:

- Verify user identity for certain services (Art. 16a)
- Implement trusted flaggers and complaint mechanisms (Art. 22)
- Provide transparency about content moderation (Art. 15)

**miTch enables DSA compliance without mass surveillance:**

- Platforms can verify "real person, 18+, EU resident" ✓
- Users retain privacy while meeting legal requirements ✓
- Overreaching platforms face collective accountability ✓

---

## Demo Scenario: FlirtRadar™

A fictional dating app with low trust score (35/100) requests maximum data:

1. **Request:** 7 attributes including biometrics and social graph
2. **miTch Analyse:** 🔴 High risk — structural blocks active on 5/7 fields
3. **Proof:** Pseudonymous login generated (age + pairwise ID only)
4. **Result:** "App wanted everything — got almost nothing"
5. **Flag option:** User can report FlirtRadar as overreaching

**See:** Live demo at [late-bloomer420.github.io/miTch](https://late-bloomer420.github.io/miTch/) → Social Login tab

---

## Implementation Dependencies

| Component                 | Package                | Status                                             |
| ------------------------- | ---------------------- | -------------------------------------------------- |
| Pairwise DID derivation   | `@mitch/shared-crypto` | ✅ Implemented                                     |
| `isOver18` predicate      | `@mitch/predicates`    | ✅ Implemented                                     |
| Policy Engine deny codes  | `@mitch/policy-engine` | ✅ Implemented (needs social-login-specific rules) |
| OID4VP presentation flow  | `@mitch/oid4vp`        | ✅ Implemented                                     |
| Collective Signal         | `@mitch/policy-engine` | ⚠️ Concept only (see student-discount-ibk.md)      |
| Social-login policy rules | `@mitch/policy-engine` | ❌ Not yet implemented                             |
| DSA complaint generator   | —                      | ❌ Not yet implemented                             |

### New Deny Codes Needed

```typescript
// Social Login specific deny codes
DENY_BIOMETRIC_BLOCKED; // profile_photo, fingerprint, voice
DENY_SOCIAL_GRAPH_BLOCKED; // friends_list, contacts, followers
DENY_LOCATION_BLOCKED; // location_history, GPS, cell tower
DENY_DEVICE_FINGERPRINT_BLOCKED; // device_id, hardware_id, IMEI
```

---

## Roadmap

1. **Now:** Documentation + demo (this document + standalone.html) ✅
2. **Next:** Add social-login deny codes to Policy Engine
3. **Next:** Create social-login policy rule template
4. **Later:** Collective Signal aggregation (shared with Student Discount use case)
5. **Future:** DSA complaint auto-generation
6. **Future:** Platform adoption outreach (start with privacy-first platforms)

---

_"Login with Google tells the app who you are. miTch tells the app what you qualify for."_
