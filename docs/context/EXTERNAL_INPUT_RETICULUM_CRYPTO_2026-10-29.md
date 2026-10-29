# External Input: Reticulum Cryptographic Primitives (reticulum.network/crypto.html)

**Date:** 2026-10-29
**Type:** External research input, not a product decision or dependency proposal.
**Source:** https://reticulum.network/crypto.html (fetched 2026-10-29)
**Status:** Read-only observation. No commitment, no backlog change.

## What the source is

Reticulum is a cryptography-focused networking stack for decentralized /
off-grid communication. The page lists its authoritative cryptographic
primitives (Ed25519, X25519, HKDF, AES-256-CBC, HMAC-SHA256, SHA-256/512) and
states two governance rules:

1. The primitive list is **authoritative**: anything claiming to be Reticulum
   but not using exactly these primitives "is not Reticulum", possibly a
   compromised clone.
2. If the OpenSSL backend is unavailable, a pure-Python fallback exists, and
   using it is an **explicitly flagged risk decision** (less scrutiny, no
   external audit of the whole system).

## Why this is NOT a miTch analogue

Reticulum operates at the transport/trust layer (how endpoints encrypt and
sign). miTch operates at the disclosure/policy layer (what and how much data a
verifier receives, per SD-JWT VC / OID4VP). There is no conceptual overlap in
selective disclosure, data minimization or post-consent control. Recording this
here explicitly so nobody later mistakes this note for a validated
architectural parallel.

## What miTch can still learn (transferable governance patterns)

These are three governance/communication patterns, not crypto or
architecture decisions:

1. **Authoritative primitive list as identity.** Reticulum treats "which exact
   crypto primitives" as part of its identity and publicly defines deviation as
   a sign of a compromised clone. miTch equivalent: a canonical, versioned list
   of the crypto/profile choices (e.g. SD-JWT VC hash algorithm, signature
   suites, PQC posture per SLH-DSA work) that we declare authoritative, so
   clones/forks that silently weaken them can be named as such.
2. **Fidelity tiers with explicit risk labels.** Reticulum distinguishes
   audited OpenSSL backend vs. unreviewed pure-Python fallback and requires the
   operator to make an informed, explicit choice. miTch equivalent: our
   fail-closed principle already does this for verification failures; the same
   pattern could apply to any "reduced assurance" mode (e.g. mock/soft
   verification in dev builds) — every fallback must be visible and labeled,
   never silent.
3. **Honest limitation statements.** The page says plainly: not externally
   audited, may contain security-breaking bugs, help sponsor an audit. This is
   the same posture as `docs/MATURITY_AND_LIMITATIONS.md` — a good confirmation
   that stating limits openly does not undermine the project.

## Explicitly out of scope

- No Reticulum dependency, integration or protocol reuse is proposed.
- No change to miTch crypto choices, ADRs or the security roadmap.
- Open questions (token harvesting, device farms, verifier collusion) are
  unaffected.

## Follow-ups

Issues created from this note ask for (a) a canonical crypto/profiles
reference document and (b) an inventory of reduced-assurance fallbacks — see
cross-links added to those issues once created.
