/**
 * Public domain model for the embeddable consent surface.
 *
 * Decoupled at runtime from @askmi/policy-engine (the adapter in policy-adapter.ts
 * maps a Decision + DisclosureRequest into a ConsentRequest). The model below is
 * intentionally minimal so the component can be embedded in any verifier UI.
 */

export type ClaimPolicyState =
    | 'requested'      // verifier asked for it, no policy verdict yet — user decides
    | 'allowed'        // policy ALLOWs by default (rare for raw claims; common for predicates)
    | 'denied';        // policy DENIES — user cannot opt in

export interface ClaimItem {
    /** Stable claim key, e.g. "age", "birthDate". */
    key: string;
    /** Human label. If absent, key is shown. */
    label?: string;
    /** Optional non-sensitive preview (NEVER the raw secret). e.g. "***@example.com". */
    preview?: string;
    /** Verdict from policy. Drives initial UI state and toggleability. */
    policyState: ClaimPolicyState;
    /** Stable reason code if denied. */
    reason?: string;
}

export interface PredicateItem {
    /** Stable predicate id, e.g. "age_over_18". */
    id: string;
    claim: string;
    operation: string;
    value: unknown;
    label?: string;
    policyState: ClaimPolicyState;
    reason?: string;
}

export interface VerifierIdentity {
    /** DID or canonical id. Hashed in the receipt — never displayed raw without sanitization. */
    id: string;
    /** Human-readable name to display. */
    displayName?: string;
}

export interface ConsentRequest {
    requestId: string;
    verifier: VerifierIdentity;
    purpose: string;
    claims: ClaimItem[];
    predicates: PredicateItem[];
    /** Optional reference to the policy that produced this request. */
    policy?: { id: string; version: string; hash?: string };
}

export type ConsentVerdict = 'CONSENTED' | 'WITHHELD' | 'CANCELLED';

export interface ConsentResult {
    requestId: string;
    verdict: ConsentVerdict;
    allowedClaims: string[];
    allowedPredicateIds: string[];
    withheldClaims: string[];
    withheldPredicateIds: string[];
    timestamp: string;
}

/**
 * A minimization-safe receipt: hash-linked to the request + policy, but contains
 * no raw claim values. Shape is compatible with policy-engine DecisionCapsule
 * conventions (verifierRef as sha256, no rawClaimsStored).
 */
export interface ConsentReceipt {
    receiptId: string;
    requestId: string;
    /** sha256(verifier.id), prefixed "sha256:" — matches DecisionCapsule.verifierRef. */
    verifierRef: string;
    purpose: string;
    verdict: ConsentVerdict;
    allowedClaims: string[];
    allowedPredicateIds: string[];
    withheldClaims: string[];
    withheldPredicateIds: string[];
    /** sha256 of the canonical request (claims/predicates/purpose/verifier id). */
    requestHash: string;
    /** Policy hash if provided to the adapter. */
    policyHash?: string;
    timestamp: string;
    rawClaimsStored: false;
}

export interface ConsentTheme {
    colorBg?: string;
    colorSurface?: string;
    colorBorder?: string;
    colorText?: string;
    colorMuted?: string;
    colorAllow?: string;
    colorWithhold?: string;
    colorDeny?: string;
    colorAccent?: string;
    radius?: string;
    fontFamily?: string;
}

export interface ConsentStrings {
    title: string;
    purposePrefix: string;
    sectionClaims: string;
    sectionPredicates: string;
    stateRequested: string;
    stateAllowed: string;
    stateWithheld: string;
    stateDenied: string;
    btnApprove: string;
    btnCancel: string;
    emptyClaims: string;
    emptyPredicates: string;
    deniedByPolicy: string;
    failClosedHint: string;
}
