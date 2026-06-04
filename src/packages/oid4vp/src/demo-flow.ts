/**
 * OID4VP Demo Flow Orchestrator — Session 9 (W-01 through W-05)
 *
 * Wires together: OID4VP + SD-JWT VC + Key Binding JWT for an
 * end-to-end presentation flow. Works in both Node.js (tests/backend)
 * and browser environments (WebCrypto-only).
 *
 * Flow:
 *   Verifier: buildOID4VPRequest()        → W-01
 *   Wallet:   buildSDJWTPresentation()    → W-03
 *   Verifier: validateSDJWTPresentation() → W-04
 *   Both:     buildSessionCleanup()       → W-05
 */

import {
  issueSDJWTVC,
  validateSDJWTVC,
  createKeyBindingJWT,
  validateKeyBindingJWT,
  buildCNFClaim,
  statusResolver,
  trustListResolver,
  type SDJWTVCPayload,
} from '@askmi/shared-crypto';
import type { JWK } from 'jose';
import { ASKMI_SCENARIO_VCT } from '@askmi/shared-types';
import type { AuthorizationRequest, PresentationDefinition, PresentationSubmission } from './types';

// ─── Cross-env random helper ──────────────────────────────────────────────────

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ─── W-01: Scenario → Presentation Definition ────────────────────────────────

/** Per-scenario OID4VP Presentation Definitions (HAIP: limit_disclosure=required) */
export const SCENARIO_PRESENTATION_DEFINITIONS: Record<string, PresentationDefinition> = {
  'liquor-store': {
    id: 'pd-age-verification',
    name: 'Age Verification',
    purpose: 'Verify that the holder is at least 18 years old',
    input_descriptors: [
      {
        id: 'age-credential',
        name: 'Age Credential',
        purpose: 'Prove age ≥ 18',
        constraints: {
          limit_disclosure: 'required',
          fields: [{ path: ['$.age'], filter: { type: 'number', minimum: 18 } }],
        },
      },
    ],
  },
  'doctor-login': {
    id: 'pd-professional-identity',
    name: 'Professional Identity',
    purpose: 'Verify professional medical credentials',
    input_descriptors: [
      {
        id: 'age-descriptor',
        name: 'Age',
        constraints: {
          limit_disclosure: 'required',
          fields: [{ path: ['$.age'] }],
        },
      },
      {
        id: 'professional-descriptor',
        name: 'Professional Role',
        constraints: {
          limit_disclosure: 'required',
          fields: [{ path: ['$.role'] }, { path: ['$.licenseId'] }],
        },
      },
    ],
  },
  'ehds-er': {
    id: 'pd-patient-summary',
    name: 'Patient Summary (EHDS)',
    purpose: 'Emergency access to patient medical data',
    input_descriptors: [
      {
        id: 'patient-summary',
        name: 'Patient Summary',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            { path: ['$.bloodGroup'] },
            { path: ['$.allergies'] },
            { path: ['$.emergencyContacts'] },
          ],
        },
      },
    ],
  },
  pharmacy: {
    id: 'pd-prescription',
    name: 'Prescription',
    purpose: 'Verify valid prescription for medication dispensing',
    input_descriptors: [
      {
        id: 'prescription',
        name: 'Prescription',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            { path: ['$.medication'] },
            { path: ['$.dosageInstruction'] },
            { path: ['$.refillsRemaining'] },
          ],
        },
      },
    ],
  },
  revoked: {
    id: 'pd-revoked-credential-test',
    name: 'Revoked Credential Test',
    purpose: 'Test revocation detection',
    input_descriptors: [
      {
        id: 'revoked-credential',
        name: 'Revoked Credential',
        constraints: {
          limit_disclosure: 'required',
          fields: [{ path: ['$.age'] }],
        },
      },
    ],
  },
};

export const SCENARIO_LABELS: Record<string, string> = {
  'liquor-store': 'Liquor Store (Age Verification)',
  'doctor-login': 'Doctor Login (Professional Identity)',
  'ehds-er': 'EHDS Emergency (Patient Summary)',
  pharmacy: 'Pharmacy (Prescription)',
  revoked: 'Revoked Credential (Test)',
};

export const SCENARIO_VCT: Record<string, string> = ASKMI_SCENARIO_VCT;

// ─── W-01: Authorization Request Builder ─────────────────────────────────────

export interface BuildRequestOpts {
  verifierClientId: string;
  redirectUri: string;
  scenarioId: string;
  clientName?: string;
}

export interface BuildRequestResult {
  request: AuthorizationRequest;
  nonce: string;
}

/**
 * W-01: Build a spec-conformant OID4VP Authorization Request for a given scenario.
 * Returns the request and the nonce (which the verifier must store for replay detection).
 */
export function buildOID4VPRequest(opts: BuildRequestOpts): BuildRequestResult {
  const pd = SCENARIO_PRESENTATION_DEFINITIONS[opts.scenarioId];
  if (!pd) throw new Error(`Unknown scenario: ${opts.scenarioId}`);

  const nonce = randomHex(16);

  const request: AuthorizationRequest = {
    response_type: 'vp_token',
    client_id: opts.verifierClientId,
    redirect_uri: opts.redirectUri,
    nonce,
    presentation_definition: pd,
    response_mode: 'direct_post',
    state: randomHex(8),
    client_metadata: {
      client_name: opts.clientName ?? SCENARIO_LABELS[opts.scenarioId] ?? opts.scenarioId,
    },
  };

  return { request, nonce };
}

// ─── W-03: Presentation Builder ──────────────────────────────────────────────

export interface BuildPresentationOpts {
  /** OID4VP Authorization Request from the verifier */
  request: AuthorizationRequest;
  /** Issuer's private ECDSA key (signs the SD-JWT VC) */
  issuerPrivateKey: CryptoKey;
  /** Holder's ECDSA key pair (public key bound in cnf; private key signs KB-JWT) */
  holderKeyPair: { privateKey: CryptoKey; publicKey: CryptoKey };
  /** Full credential claims available in the wallet */
  claims: Record<string, unknown>;
  /** Credential type URI (per SCENARIO_VCT) */
  vct: string;
  /** Issuer DID/URI (must be a URI per SD-JWT VC draft-11) */
  issuerDid: string;
  /** If true, embed a status claim to simulate a revoked credential */
  revoked?: boolean;
  /** StatusList2021 credential URL used when `revoked` is true. */
  statusListUri?: string;
}

export interface BuildPresentationResult {
  /** SD-JWT VC VP token string: {sd-jwt-vc}~{kb-jwt} */
  vpTokenString: string;
  /** OID4VP Presentation Submission */
  presentationSubmission: PresentationSubmission;
  /** Only the claims actually included (selective disclosure) */
  disclosedClaims: Record<string, unknown>;
}

/**
 * W-03: Build an SD-JWT VC Presentation with Key Binding JWT.
 *
 * Selective disclosure: only claims requested by the Presentation Definition
 * are included in the credential. All other claims are withheld.
 */
export async function buildSDJWTPresentation(
  opts: BuildPresentationOpts
): Promise<BuildPresentationResult> {
  const { request, issuerPrivateKey, holderKeyPair, claims, vct, issuerDid } = opts;
  const now = Math.floor(Date.now() / 1000);

  // Collect requested claim paths from the PD
  const requestedKeys = new Set<string>();
  for (const desc of request.presentation_definition.input_descriptors) {
    for (const field of desc.constraints?.fields ?? []) {
      for (const path of field.path) {
        const match = /^\$\.(.+)$/.exec(path);
        if (match) requestedKeys.add(match[1]);
      }
    }
  }

  // Filter to only requested claims
  const disclosedClaims: Record<string, unknown> = {};
  for (const key of Object.keys(claims)) {
    if (requestedKeys.has(key)) {
      disclosedClaims[key] = claims[key];
    }
  }

  // Build cnf claim (holder's public key for Key Binding)
  const cnf = await buildCNFClaim(holderKeyPair.publicKey);

  // Build SD-JWT VC payload
  const payload: Omit<SDJWTVCPayload, '_sd_alg'> & { vct: string; iss: string } = {
    iss: issuerDid,
    vct,
    iat: now,
    exp: now + 3600,
    cnf,
    ...disclosedClaims,
  };

  // Simulate revocation: embed status claim
  if (opts.revoked) {
    (payload as SDJWTVCPayload).status = {
      status_list: { idx: 42, uri: opts.statusListUri ?? 'https://example.com/status-list/1' },
    };
  }

  // Issue SD-JWT VC (signed by issuer)
  const sdJwtVc = await issueSDJWTVC(payload, issuerPrivateKey);

  // SD-JWT with disclosures (no additional disclosures in this simple presentation)
  const sdJwtWithDisclosures = `${sdJwtVc}~`;

  // Create Key Binding JWT (signed by holder, binds nonce + aud + sd_hash)
  const kbJwt = await createKeyBindingJWT(
    { aud: request.client_id, nonce: request.nonce, sdJwtWithDisclosures },
    holderKeyPair.privateKey
  );

  // Final VP token: {sd-jwt-vc}~{kb-jwt}
  const vpTokenString = `${sdJwtVc}~${kbJwt}`;

  const submissionId = randomHex(8);
  const presentationSubmission: PresentationSubmission = {
    id: `sub-${submissionId}`,
    definition_id: request.presentation_definition.id,
    descriptor_map: request.presentation_definition.input_descriptors.map((desc, i) => ({
      id: desc.id,
      format: 'sd-jwt',
      path: request.presentation_definition.input_descriptors.length === 1 ? '$' : `$[${i}]`,
    })),
  };

  return { vpTokenString, presentationSubmission, disclosedClaims };
}

// ─── W-04: Presentation Validator ────────────────────────────────────────────

export interface ValidatePresentationOpts {
  vpTokenString: string;
  presentationSubmission: PresentationSubmission;
  request: AuthorizationRequest;
  /** Issuer's public key to verify the SD-JWT VC signature */
  issuerPublicKey: CryptoKey;
  /** Reject credentials with a status claim (simulates revocation check) */
  checkRevocation?: boolean;
  /** Check if the issuer is in the EUDI Trust List (TSL) */
  checkTrust?: boolean;
}

export interface ValidatePresentationResult {
  ok: boolean;
  disclosedClaims?: Record<string, unknown>;
  errors: string[];
}

/**
 * W-04: Validate an SD-JWT VC Presentation.
 *
 * Checks:
 *  1. SD-JWT VC issuer signature
 *  2. Credential expiry / revocation
 *  3. cnf.jwk presence (Key Binding required)
 *  4. KB-JWT: nonce binding, audience binding, iat freshness, sd_hash
 */
export async function validateSDJWTPresentation(
  opts: ValidatePresentationOpts
): Promise<ValidatePresentationResult> {
  const {
    vpTokenString,
    request,
    issuerPublicKey,
    checkRevocation = true,
    checkTrust = false,
  } = opts;

  // Split VP token: last segment after final ~ is KB-JWT
  const parts = vpTokenString.split('~');
  if (parts.length < 2) {
    return { ok: false, errors: ['VP token must contain SD-JWT VC and KB-JWT separated by ~'] };
  }

  const kbJwt = parts[parts.length - 1];
  const sdJwtWithDisclosures = parts.slice(0, parts.length - 1).join('~') + '~';
  const sdJwtVc = parts[0];

  // Step 1: Validate SD-JWT VC
  const vcResult = await validateSDJWTVC(sdJwtVc, issuerPublicKey);
  if (!vcResult.ok) {
    return { ok: false, errors: vcResult.errors };
  }
  const payload = vcResult.payload!;

  // Step 2a: Trust List (TSL) check
  if (checkTrust) {
    const trustResult = await trustListResolver.isIssuerTrusted(payload.iss, 'high');
    if (!trustResult.isTrusted) {
      return {
        ok: false,
        errors: [trustResult.reason || `Issuer untrusted (not in EUDI TSL): ${payload.iss}`],
      };
    }
  }

  // Step 2b: Revocation check (live StatusList check)
  if (checkRevocation && payload.status) {
    const result = await statusResolver.checkStatus(payload.status, 'high');
    if (result.decision === 'DENY') {
      return {
        ok: false,
        errors: [
          result.reason ||
            result.denyCode ||
            `Credential revoked (status_list idx: ${payload.status.status_list.idx})`,
        ],
      };
    }
  }

  // Step 3: Extract holder JWK from cnf — pass JWK directly to avoid
  // Node.js KeyObject vs Web CryptoKey instanceof mismatch in jose.
  const holderJWK = payload.cnf?.jwk as JWK | undefined;
  if (!holderJWK) {
    return { ok: false, errors: ['Missing cnf.jwk — Key Binding not possible'] };
  }

  // Step 4: Validate Key Binding JWT
  const kbResult = await validateKeyBindingJWT(kbJwt, holderJWK, {
    expectedAud: request.client_id,
    expectedNonce: request.nonce,
    sdJwtWithDisclosures,
    maxAgeSeconds: 600,
  });
  if (!kbResult.ok) {
    return { ok: false, errors: kbResult.errors };
  }

  // Step 5: Extract disclosed claims (strip SD-JWT VC metadata)
  const METADATA_KEYS = new Set([
    'iss',
    'vct',
    'iat',
    'exp',
    'nbf',
    'sub',
    'cnf',
    'status',
    '_sd',
    '_sd_alg',
  ]);
  const disclosedClaims: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (!METADATA_KEYS.has(k)) {
      disclosedClaims[k] = v;
    }
  }

  return { ok: true, disclosedClaims, errors: [] };
}

// ─── W-05: Session Cleanup ────────────────────────────────────────────────────

export interface ConsentReceipt {
  id: string;
  verifier: string;
  purpose: string;
  claimsShared: string[];
  timestamp: string;
  /**
   * DecisionCapsule.decision_id from the fail-closed policy evaluation that
   * produced this presentation outcome. Binds the user-visible consent
   * receipt to the authoritative policy decision (audit/forensic linkage).
   * `null` only when no policy evaluation ran (e.g. ERROR before evaluate()).
   */
  decisionId?: string | null;
}

export interface SessionCleanupResult {
  consentReceipt: ConsentReceipt;
  auditEntry: {
    presentationId: string;
    verifier: string;
    timestamp: string;
    claimsShared: string[];
    outcome: 'SUCCESS' | 'DENIED' | 'ERROR';
    /** DecisionCapsule.decision_id — mirrors `consentReceipt.decisionId`
     *  in the forensic audit entry. See ConsentReceipt.decisionId. */
    decisionId?: string | null;
  };
}

/**
 * W-05: Generate consent receipt and audit entry after a presentation.
 * Call this regardless of outcome to ensure auditability.
 * Ephemeral key material (issuer/holder key pairs) should be discarded
 * after calling this function.
 */
export function buildSessionCleanup(opts: {
  request: AuthorizationRequest;
  disclosedClaims: Record<string, unknown>;
  outcome: 'SUCCESS' | 'DENIED' | 'ERROR';
  /**
   * DecisionCapsule.decision_id from the policy evaluation that drove this
   * outcome. Recorded in both `consentReceipt` and `auditEntry` to bind the
   * receipt to the fail-closed decision. Pass `null` when no evaluation
   * ran; the field is preserved (not dropped) so downstream audit logs can
   * distinguish "no decision" from "missing field".
   */
  decisionId?: string | null;
}): SessionCleanupResult {
  const { request, disclosedClaims, outcome, decisionId = null } = opts;
  const timestamp = new Date().toISOString();
  const presentationId = randomHex(8);
  const claimsShared = Object.keys(disclosedClaims);

  return {
    consentReceipt: {
      id: `consent-${presentationId}`,
      verifier: request.client_id,
      purpose: request.presentation_definition.purpose ?? 'Verification',
      claimsShared,
      timestamp,
      decisionId,
    },
    auditEntry: {
      presentationId,
      verifier: request.client_id,
      timestamp,
      claimsShared,
      outcome,
      decisionId,
    },
  };
}
