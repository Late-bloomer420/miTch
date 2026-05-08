export type Verdict = 'ALLOW' | 'DENY' | 'PROMPT';

export type ResponseMode = 'NONE' | 'RAW_CLAIM' | 'PREDICATE_PROOF' | 'SIGNED_ATTESTATION';

export interface PredicateRequest {
  claim: string;
  operation: string;
  value: unknown;
}

export interface DisclosureRequest {
  requestId: string;
  verifierDid: string;
  purpose: string;
  requestedClaims: string[];
  requestedPredicates: PredicateRequest[];
  nonce?: string;
  audience?: string;
  timestamp?: string;
}

export interface Policy {
  id: string;
  version: string;
  scope: {
    verifierPattern: string;
    purpose: string;
  };
  defaults: {
    blockUnknownVerifiers: boolean;
    requiresTrustedIssuer: boolean;
    requiresUserConsent: boolean;
    requiresPresence: boolean;
    failClosed: boolean;
  };
  allowedClaims: string[];
  allowedPredicates: Array<{
    id: string;
    claim: string;
    operation: string;
    value: unknown;
    responseMode: 'PREDICATE_PROOF';
  }>;
  deniedClaims: Array<{
    claim: string;
    reason: PolicyReasonCode;
  }>;
  linkabilityControls: {
    pairwiseDidRequired: boolean;
    audienceBindingRequired: boolean;
    nonceRequired: boolean;
    denyReusableProofs: boolean;
  };
}

export interface Decision {
  verdict: Verdict;
  responseMode: ResponseMode;
  policyId: string;
  requestId: string;
  allowedDisclosure?: {
    type: 'predicate';
    claim: string;
    operation: string;
    value: unknown;
  };
  deniedClaims: string[];
  reasonCodes: PolicyReasonCode[];
  rawClaimsDisclosed: false;
}

import type { PolicyReasonCode } from './reasonCodes';
