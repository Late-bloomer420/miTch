/**
 * Server-scope evaluation fixture for the MCP server (CI-01).
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  NON-AUTHORITATIVE MOCK SCOPE — NOT A REAL WALLET.                         │
 * │                                                                           │
 * │  docs/mcp-server-architecture.md §10.3 deliberately froze the disclosure  │
 * │  wiring with the reasoning: "ein embedded Default produziert echte        │
 * │  Decisions ohne autorisierte Policy". This module honours that concern by │
 * │  making BOTH the policy AND the credential inventory an explicit,         │
 * │  clearly-labelled mock. The PolicyEngine runs for real, but the inputs    │
 * │  are synthetic, so no decision here is authoritative. Every tool response │
 * │  built from this scope is tagged `scope: "mock"`.                         │
 * │                                                                           │
 * │  When a real wallet is wired (v2 — see §9.2 MITCH_WALLET_DB), this module │
 * │  is replaced by a loader that reads the user's authorised policy and      │
 * │  credential metadata. The tool contract (sanitised output) stays the same.│
 * └─────────────────────────────────────────────────────────────────────────┘
 */

import type {
  PolicyManifest,
  StoredCredentialMetadata,
} from '@askmi/shared-types';

/** Synthetic holder DID used for the mock evaluation scope. */
export const MOCK_USER_DID = 'did:example:mock-holder';

/** Synthetic issuer DID — obviously fake; never a real trust anchor. */
export const MOCK_ISSUER_DID = 'did:example:mock-gov-issuer';

/** Well-known verifier DIDs the mock policy recognises (for documentation/tests). */
export const MOCK_VERIFIERS = {
  /** Auto-allow (age check, no consent gate). */
  liquorStore: 'did:web:liquor-store.example.com',
  /** Matches a rule but requires explicit user consent → PROMPT. */
  hospital: 'did:web:hospital.example.com',
} as const;

/**
 * Mock credential inventory. StoredCredentialMetadata never carries claim
 * *values* — only claim names, issuer and id — but even those identifiers are
 * synthetic here and must never leak to the agent (see sanitize.ts).
 */
export const MOCK_CREDENTIALS: StoredCredentialMetadata[] = [
  {
    id: 'mock-vc-age-0001',
    issuer: MOCK_ISSUER_DID,
    type: ['VerifiableCredential', 'AgeCredential'],
    issuedAt: new Date(Date.now() - 30 * 86_400_000).toISOString(),
    expiresAt: new Date(Date.now() + 365 * 86_400_000).toISOString(),
    claims: ['age_over_18', 'dateOfBirth'],
  },
];

/**
 * Mock policy manifest. Three deterministic outcomes for the wiring:
 *   - liquor-store  → ALLOW  (rule matched, trusted issuer, no consent gate)
 *   - hospital      → PROMPT (rule matched but requiresUserConsent)
 *   - anything else → DENY   (blockUnknownVerifiers, fail-closed)
 */
export const MOCK_POLICY: PolicyManifest = {
  version: 'mock-1.0',
  trustedIssuers: [
    {
      did: MOCK_ISSUER_DID,
      name: 'Mock Government Issuer',
      credentialTypes: ['AgeCredential'],
    },
  ],
  rules: [
    {
      id: 'mock-liquor-store-age',
      verifierPattern: MOCK_VERIFIERS.liquorStore,
      allowedClaims: ['age_over_18'],
      requiresTrustedIssuer: true,
      requiresUserConsent: false,
      maxCredentialAgeDays: 365,
      priority: 10,
    },
    {
      id: 'mock-hospital-consent',
      verifierPattern: MOCK_VERIFIERS.hospital,
      allowedClaims: ['age_over_18'],
      requiresTrustedIssuer: true,
      requiresUserConsent: true,
      maxCredentialAgeDays: 365,
      priority: 10,
    },
  ],
  globalSettings: {
    // Fail-closed: any verifier without a matching rule is denied outright.
    blockUnknownVerifiers: true,
  },
};
