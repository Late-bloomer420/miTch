# DECISION-006: Recovery

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 0–2

---

## Summary

Credential re-issuance for Phase 0 (fresh start, always works). Encrypted cloud backup for Phase 1. Social recovery probably never — offline recovery key covers the same need at 5% of the complexity.

---

## What Needs Recovering

| Asset | Importance | Can Re-Create? |
|---|---|---|
| Credentials (SD-JWTs) | High | ✅ Re-issue from original source |
| Consent receipts | Medium | ❌ Gone if lost |
| Wallet keys | Critical | ❌ New keys = new identity |
| Consent preferences | Low | ✅ User re-approves |

**Key insight:** Credentials are replaceable, keys are not, receipts are nice-to-have.

---

## Recovery Tiers

### Tier 1: Credential Re-Issuance (Phase 0) ✅

```
New phone → Install wallet → Re-authenticate with state provider
  → New credential issued → Old credential revoked
```

Works because the issuer adapter flow is repeatable. Revocation of old credentials via:
1. Web portal (authenticate with state provider, see active indexes, revoke)
2. New wallet auto-revokes old credentials (state provider returns same pseudonymous link)

### Tier 2: Encrypted Cloud Backup (Phase 1)

**What's backed up:** Consent receipts, preferences, credential metadata, wallet config.  
**What's NEVER backed up:** Private keys, credentials themselves, raw PII.

Encryption: XChaCha20-Poly1305, key derived from user's recovery passphrase via Argon2id. Cloud provider sees only an encrypted blob.

Destinations: iCloud / Google Drive / self-hosted WebDAV / no backup.

### Tier 3: Social Recovery — NOT RECOMMENDED

**Cost-benefit analysis:**
- Engineering: 3-6 weeks (Shamir SSS, guardian management, shard distribution UX)
- UX complexity: Explaining "give 5 QR codes to 5 people" to non-technical users
- Support burden: "My friend lost the QR code" / "We're not friends anymore"
- Target users who need it AND can use it: vanishingly small

**Simpler alternative:** Offline recovery key export.

```
┌────────────────────────────────┐
│  KFBR-392X-MPLT-7VN2-QW89     │
│                                │
│  Write this down. Store it     │
│  somewhere safe.               │
│  Options: Copy | Print | QR    │
└────────────────────────────────┘
```

30 minutes to build. Users understand "write down a code." Covers the same scenario as social recovery for anyone who stores the key in a safe, with a trusted person, etc.

---

## Recovery Matrix

| Scenario | Outcome |
|---|---|
| Lost phone + have backup key | Full recovery ✅ |
| Lost phone + lost key + have guardians | Full recovery ✅ (if social recovery built) |
| Lost phone + lost key + no guardians | Partial ⚠️ — credentials re-issued, history gone |
| Lost phone + no backup at all | Fresh start ⚠️ — wallet works, history gone |

**Even worst case is not catastrophic.** User re-authenticates, gets fresh credentials, is operational immediately. Loses history, not functionality.

---

## Crypto-Shredding Interaction

Old credential on old device → inaccessible (device lost).  
Old credential on server → doesn't exist (crypto-shredded at issuance).  
New credential → freshly issued with new K_trans on new device.

System is self-healing. Loss of keys = loss of data = exactly what crypto-shredding promises.

---

## What NOT to Build

| Anti-Pattern | Why |
|---|---|
| Email-based recovery | PII stored server-side |
| SMS recovery codes | SIM swap attacks |
| Security questions | Weak, guessable, stored server-side |
| Admin override / master key | Defeats self-sovereignty |
| Key escrow with miTch | miTch can access wallets → trust violation |

---

## Phase Deliverables

| Feature | Phase |
|---|---|
| Credential re-issuance (fresh start) | 0 ✅ |
| Old credential revocation via web portal | 0 ✅ |
| Auto-revoke old creds on re-issuance | 0 ✅ |
| Offline recovery key export (print/QR) | 1 |
| Encrypted cloud backup | 1 |
| Social recovery | Probably never — wait for user demand |
