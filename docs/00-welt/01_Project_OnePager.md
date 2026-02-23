# miTch — Project One‑Pager

## What it is
**miTch** is a **user-sovereign identity & authorization system** built to enable *verifiable trust without centralized data custody*.
It enforces **privacy, proportionality, and compliance by architecture and cryptography** (not by “policy promises”).

## What it is for
- **Selective disclosure**: prove what a requester needs (e.g., “over 18”, “resident in EU”, “licensed professional”) without exposing raw identity records.
- **Regulated environments** (EU-first): create auditability and assurance while minimizing personal data exposure.
- **AI orchestration boundary**: when an AI orchestrator calls other AIs/services, miTch-style policy gates ensure only minimal, allowed information can flow.

## Non-negotiables
- **Edge-first decisions**: identity + authorization decisions happen on the user’s device.
- **Ephemerality by default**: personal data exists transactionally; key destruction = erasure.
- **Data minimization by construction**: if not strictly required, it must not be processed.
- **User as root of trust**: no hidden authorities, backdoors, silent delegation.
- **Fail-closed**: ambiguity ⇒ deny.

## Core idea (PII boundary)
- **PII stays in the state/issuer domain** (e.g., passport registry, national eID backends).
- miTch never needs raw passport data; it only handles **cryptographic proofs/claims** sufficient for the request purpose.
- Requesters receive **the minimal proof**, not the underlying attributes.

## What makes it different
- Not a data broker; no profiling.
- Not blockchain-dependent.
- Not a speculative crypto wallet.
- Not “anonymity at all costs”: supports accountability via authorized disclosures.

## Typical flow (high level)
1. Requester sends a request + policy requirements (claims, purpose, retention, allowed uses).
2. User device validates the request against local policy.
3. If allowed, the user device produces **a proof** (ZK / signed attestation / derived claim) and sends it.
4. Requester verifies the proof and logs an auditable receipt.
