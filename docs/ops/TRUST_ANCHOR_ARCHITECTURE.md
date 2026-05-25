# Operational Architecture: Trust Anchors & EUDI Trust List (TSL)

## 1. Overview
In the EUDI Wallet ecosystem, trust is established through a chain of verifiable credentials and identifiers. For a presentation to be valid, the Verifier must trust the Wallet's Issuer, and the Wallet must trust the Verifier's Attestation.

This document describes the current "Mock" trust architecture used for local development and the "Live" architecture required for official EUDI pilot participation.

## 2. The Current "Mock" Workaround
To enable rapid prototyping without a live eIDAS Node, miTch currently employs **Static Trust Lists**.

### Wallet Side (Issuer Trust)
- **File**: `src/apps/wallet-pwa/src/data/DemoPolicy.ts`
- **Mechanism**: The `PolicyManifest` contains a `trustedIssuers` array.
- **Wiring**: The `PolicyEngine` checks if `credential.iss` matches a DID in the `trustedIssuers` list.
- **Limitation**: Any new issuer must be manually added to the source code or local database.

### Verifier Side (Wallet Trust)
- **File**: `src/apps/verifier-demo/backend/src/app.ts`
- **Mechanism**: The `trustedIssuers` array in the verifier's session state (or environment variables).
- **Wiring**: When a VP is received, the verifier checks the `iss` claim of the SD-JWT VC against this list.
- **Limitation**: Does not verify the actual eIDAS status of the issuer.

## 3. The Target "Live" Architecture (TSL)
The transition to 100% compliance requires the use of the **EU Trusted List (TSL)**.

### EUDI Trust List Resolver
The `EUDITrustListResolver` (`@mitch/shared-crypto`) replaces static lists with dynamic lookups.

1. **Source**: Fetches the official TSL from an EU-managed endpoint (e.g., `https://ec.europa.eu/.../lotl.xml` or a JSON-wrapped mirror).
2. **Caching**: Implements a 24-hour cache with a "fail-closed" grace period.
3. **Verification**: Validates the cryptographic signature of the TSL itself using the EU Root Certificate.

### Deployment Wiring
To switch from Mock to Live, set the following environment variables:

```powershell
# Enable Live Trust Resolution
$env:MITCH_TRUST_MODE = "live"

# Official TSL Endpoint (or compliant mirror)
$env:MITCH_TSL_URL = "https://trust.mitch.demo/v1/eudi-lotl.json"

# EU Root Cert Fingerprint (for TSL validation)
$env:MITCH_TRUST_ROOT_SHA256 = "..."
```

## 4. Operational Failure Modes (Fail-Closed)
According to CIR 2024/2982, the system must prioritize security over availability.

| Failure Scenario | Logic | Outcome |
| :--- | :--- | :--- |
| TSL Endpoint Offline (Cache fresh) | Use Cache | **ALLOW** |
| TSL Endpoint Offline (Cache expired) | Risk Tier: High | **DENY** (Fail-Closed) |
| Invalid TSL Signature | Reject List | **DENY** |
| Entity not in TSL | Strict Lookup | **DENY** |

## 5. Migration Path
1. **Pilot Phase 1**: Maintain Mock mode for `did:example` scenarios but enable `live` mode for official interop tests.
2. **Production**: Disable `MITCH_TRUST_MODE = "mock"` entirely in the environment configuration to prevent accidental acceptance of untrusted entities.
