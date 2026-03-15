# miTch — Core Vision

> Not implementation-ready. Thinking space only.

---

## Platform Reality (non-negotiable constraint)

Users are on iOS and Android. That is the standard. We are not replacing it.
We are not building an alternative OS, an alternative app store, or an alternative phone.

Apple and Google are the platform. We accept that.
What we can do is build ON TOP of that platform in a way that makes the data layer visible —
what is being read, by whom, for what purpose — within the constraints the platform allows.

The PrivacyAuditService already captures this instinct:
it detects OS-level telemetry (Apple, Google, Microsoft), browser tracking, network risk,
and computes a privacy score per transaction. That is the seed.

The direction is not "escape Apple/Google." The direction is "make visible what happens on top of them."

---

## What miTch is today

Privacy as gatekeeping — control what leaves the wallet at a transaction checkpoint.
Selective disclosure, crypto-shredding, ephemeral keys, fail-closed policy engine.
The forgetting layer for the transaction layer.

## What the deeper problem is

Data subjects are excluded from their own data.

The user generates the data. Institutions accumulate it, analyze it, and form a picture of the user — credit risk, health risk, behavioral profile. The user has no view into that picture, no insight, no way to see what institutions see.

miTch's deeper purpose: **put the user back in the middle.** Not just controlling what gets out at a checkpoint, but giving users the same insight into their data that institutions have.

---

## The Algorithm Question

**Can users access the same picture without having institutional proprietary algorithms?**

Yes. The math is the same. What's proprietary is not the mathematics.

- Credit scoring = logistic regression / gradient boosting on behavioral features
- Insurance risk = survival models, actuarial tables (open actuarial literature)
- Medical risk = Cox proportional hazards (published in open journals)
- Ad targeting = collaborative filtering, k-means clustering

**What IS proprietary:**
1. The weights — trained on their historical dataset (not mathematically secret, just data-dependent)
2. The threshold decisions — where they draw the cutoff line (business logic, not math)
3. The raw data pipeline — they accumulated your data over years; you don't have a copy

The gap is data access + a place to hold it + compute to run models locally.
You don't need their weights to understand yourself.
Reference population data is often published (WHO, ECB, open medical cohorts).

---

## The Data Safe Problem

Any centralized store of rich personal data becomes an attack surface.
History of personal data store projects (Solid, MyData, health data wallets) confirms this.
You centralize the most sensitive data in the world behind a login screen — now it's the single most valuable target for every attacker.

**The forgetting layer is the correct answer for the transaction layer.**

But for insight you need the data to exist long enough to compute against it.
The resolution: local computation. The insight happens on the device. Nothing leaves.

---

## Three-Layer Architecture

```
Layer 1: Forgetting Layer (miTch as-is — BUILT)
  → What you share with OTHERS at a transaction checkpoint
  → Selective disclosure, crypto-shred, ephemeral keys
  → Zero accumulation on verifier side

Layer 2: Local Insight Engine (future — NOT started)
  → What YOU see about yourself
  → Same model classes as institutions, running on your device
  → Data stays local — no server, no upload, no attack surface
  → iPhone 16 / Pixel 9 are capable: Medical risk models are kilobytes,
    not gigabytes. The compute is there.

Layer 3: ZK Proof Layer (long-term — directionally correct, not practical yet)
  → How you prove properties to others without revealing underlying data
  → "My 3-year A1c average is below X" — proved without showing the raw records
  → ZK-SNARKs — computationally heavy but the direction is right
```

Principled separation of concerns:
- What leaves the device → Layer 1 (forgetting layer)
- What you compute for yourself → Layer 2 (local only, ephemeral)
- What you prove to others → Layer 3 (reveal nothing but the conclusion)

---

## Current Implementation Status (March 2026)

- **Layer 1 is built:** 26 packages, 1411 tests, policy engine with 31+ deny codes, SD-JWT VC, OID4VP, pairwise DIDs, crypto-shredding, PQC readiness
- **Layer 2 not started**
- **Layer 3 not started**
- Reference STATE_OF_MITCH.md for full details

---

## The Phone / Backdoor Problem

**Real protection:**
- App sandboxing: protects against other apps
- Apple Secure Enclave: isolates cryptographic keys, even from the OS
- On-device ML (Core ML, Neural Engine): runs locally, data doesn't leave

**Not fully protected:**
- Apple/Google as OS vendor: deep access if compelled (government orders, NSLs)
- TEE vulnerabilities: Intel SGX has real side-channel exploits (Spectre class)
- Hardware backdoors: historically not paranoid — NSA/Dual EC DRBG happened

**The trade-off:**
The attack surface shrinks dramatically, it doesn't go to zero.
"A server holding all your data" (many attackers) → "your phone" (Apple specifically OR government with legal order).
For most users: acceptable. For high-risk users (journalists, dissidents): GrapheneOS on Pixel.

The EU angle: eIDAS 2.0 EUDIW has regulatory requirements about data locality —
may eventually create legal teeth against OS-vendor access.
