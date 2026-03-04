/**
 * @module @mitch/policy-engine/deny-reason-codes
 *
 * Anti-Oracle Deny Reason Code System
 *
 * Each deny code has three audience-specific messages:
 * - User: helpful, reveals nothing about policy internals to external parties
 * - Verifier: generic, non-distinguishing (anti-oracle)
 * - Audit: full detail for compliance review
 *
 * Design: Verifiers CANNOT probe policy rules by observing different error messages.
 * Multiple distinct deny reasons map to the same verifier-facing message.
 */

/**
 * Exhaustive enum of all deny reason codes.
 * Aligned with spec 21 (Deny Reason Code Catalog) and spec 108.
 */
export enum DenyReasonCode {
  // --- Credential Lifecycle ---
  EXPIRED = 'DENY_CREDENTIAL_EXPIRED',
  REVOKED = 'DENY_CREDENTIAL_REVOKED',
  CREDENTIAL_TOO_OLD = 'DENY_CREDENTIAL_TOO_OLD',
  NO_SUITABLE_CREDENTIAL = 'DENY_NO_SUITABLE_CREDENTIAL',
  FUTURE_ISSUANCE = 'DENY_FUTURE_ISSUANCE',

  // --- Policy ---
  POLICY_MISMATCH = 'DENY_POLICY_MISMATCH',
  POLICY_MISSING = 'DENY_POLICY_MISSING',
  POLICY_UNSUPPORTED_VERSION = 'DENY_POLICY_UNSUPPORTED_VERSION',
  NO_MATCHING_RULE = 'DENY_NO_MATCHING_RULE',
  CLAIM_NOT_ALLOWED = 'DENY_CLAIM_NOT_ALLOWED',
  MINIMIZATION_VIOLATION = 'DENY_POLICY_MINIMIZATION_VIOLATION',

  // --- Layer ---
  LAYER_VIOLATION = 'DENY_LAYER_VIOLATION',

  // --- Verifier Trust ---
  UNKNOWN_VERIFIER = 'DENY_UNKNOWN_VERIFIER',
  UNTRUSTED_ISSUER = 'DENY_UNTRUSTED_ISSUER',

  // --- Binding & Replay ---
  BINDING_FAILED = 'DENY_BINDING_FAILED',
  NONCE_REPLAY = 'DENY_BINDING_NONCE_REPLAY',
  HASH_MISMATCH = 'DENY_BINDING_HASH_MISMATCH',
  AUDIENCE_MISMATCH = 'DENY_BINDING_AUDIENCE_MISMATCH',
  BINDING_EXPIRED = 'DENY_BINDING_EXPIRED',
  DOWNGRADE_ATTACK = 'DENY_DOWNGRADE_ATTACK',

  // --- Crypto ---
  CRYPTO_VERIFY_FAILED = 'DENY_CRYPTO_VERIFY_FAILED',
  UNSUPPORTED_ALGORITHM = 'DENY_CRYPTO_UNSUPPORTED_ALG',
  KEY_STATUS_INVALID = 'DENY_CRYPTO_KEY_STATUS_INVALID',

  // --- Delegation ---
  AGENT_NOT_AUTHORIZED = 'DENY_AGENT_NOT_AUTHORIZED',
  AGENT_LIMIT_EXCEEDED = 'DENY_AGENT_LIMIT_EXCEEDED',

  // --- Rate Limiting ---
  RATE_LIMIT_EXCEEDED = 'DENY_RATE_LIMIT_EXCEEDED',

  // --- Consent / Presence ---
  CONSENT_REQUIRED = 'DENY_CONSENT_REQUIRED',
  PRESENCE_REQUIRED = 'DENY_PRESENCE_REQUIRED',
  REAUTH_REQUIRED = 'DENY_REAUTH_REQUIRED',

  // --- Infrastructure ---
  STATUS_SOURCE_UNAVAILABLE = 'DENY_STATUS_SOURCE_UNAVAILABLE',
  RESOLVER_QUORUM_FAILED = 'DENY_RESOLVER_QUORUM_FAILED',
  JURISDICTION_INCOMPATIBLE = 'DENY_JURISDICTION_INCOMPATIBLE',

  // --- Conflict Resolution ---
  CONFLICT_DENY_WINS = 'DENY_CONFLICT_RESOLUTION',

  // --- Catch-all ---
  INTERNAL_SAFE_FAILURE = 'DENY_INTERNAL_SAFE_FAILURE',
}

/**
 * Audience-specific message for a deny code.
 */
export interface AudienceMessages {
  /** Helpful message for the user (wallet UI). Safe — user owns the data. */
  user: string;
  /** Generic message for the verifier. Anti-oracle: must not reveal policy details. */
  verifier: string;
  /** Full detail for audit/compliance logs. Access-controlled. */
  audit: string;
}

/**
 * Verifier-facing message buckets.
 * Multiple deny codes map to the same verifier message to prevent oracle attacks.
 */
const VERIFIER_BUCKET_GENERIC = 'Verification could not be completed.';
const VERIFIER_BUCKET_RATE = 'Request rate exceeded.';
const VERIFIER_BUCKET_USER_ACTION = 'User action required.';
const VERIFIER_BUCKET_INFRA = 'Service temporarily unavailable.';

/**
 * Complete catalog mapping each deny code to audience-specific messages.
 */
export const DENY_REASON_CATALOG: Record<DenyReasonCode, AudienceMessages> = {
  // --- Credential Lifecycle ---
  [DenyReasonCode.EXPIRED]: {
    user: 'Dein Nachweis ist abgelaufen. Bitte erneuere ihn.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Credential expired: expiresAt < evaluation timestamp.',
  },
  [DenyReasonCode.REVOKED]: {
    user: 'Dein Nachweis wurde zurückgezogen. Bitte kontaktiere den Aussteller.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Credential revoked: status-list index marked revoked by issuer.',
  },
  [DenyReasonCode.CREDENTIAL_TOO_OLD]: {
    user: 'Dein Nachweis ist zu alt für diese Anfrage. Bitte aktualisiere ihn.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Credential age exceeds maxCredentialAgeDays in matched rule.',
  },
  [DenyReasonCode.NO_SUITABLE_CREDENTIAL]: {
    user: 'Du hast keinen passenden Nachweis für diese Anfrage.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'No credential in wallet matches requirement type/claims/issuer constraints.',
  },
  [DenyReasonCode.FUTURE_ISSUANCE]: {
    user: 'Ein Nachweis hat ein ungültiges Ausstellungsdatum.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Credential issuedAt is in the future — clock skew or forgery.',
  },

  // --- Policy ---
  [DenyReasonCode.POLICY_MISMATCH]: {
    user: 'Die Anfrage entspricht nicht deinen Sicherheitseinstellungen.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Request parameters do not satisfy any policy rule constraint set.',
  },
  [DenyReasonCode.POLICY_MISSING]: {
    user: 'Keine Sicherheitsrichtlinie geladen. Bitte starte die App neu.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'PolicyManifest was null/undefined — fail-closed to DENY.',
  },
  [DenyReasonCode.POLICY_UNSUPPORTED_VERSION]: {
    user: 'Deine App benötigt ein Update für diese Anfrage.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Policy version not in KNOWN_POLICY_VERSIONS set — fail-closed.',
  },
  [DenyReasonCode.NO_MATCHING_RULE]: {
    user: 'Für diesen Service gibt es keine passende Regel.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'No policy rule verifierPattern matched request.verifierId.',
  },
  [DenyReasonCode.CLAIM_NOT_ALLOWED]: {
    user: 'Der Service fragt Daten ab, die deine Policy nicht erlaubt.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Requested claims not in allowedClaims or explicitly in deniedClaims.',
  },
  [DenyReasonCode.MINIMIZATION_VIOLATION]: {
    user: 'Der Service fragt zu viele Daten ab.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Request exceeds least-disclosure rule — minimization violation.',
  },

  // --- Layer ---
  [DenyReasonCode.LAYER_VIOLATION]: {
    user: 'Dieser Service ist nicht für diese Datenkategorie autorisiert.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Verifier minimumLayer insufficient for requested data layer.',
  },

  // --- Verifier Trust ---
  [DenyReasonCode.UNKNOWN_VERIFIER]: {
    user: 'Dieser Service ist nicht bekannt. Fortfahren auf eigenes Risiko.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Verifier DID not matched by any rule and blockUnknownVerifiers=true.',
  },
  [DenyReasonCode.UNTRUSTED_ISSUER]: {
    user: 'Der Aussteller deines Nachweises wird nicht akzeptiert.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Credential issuer DID not in policy trustedIssuers for this credential type.',
  },

  // --- Binding & Replay ---
  [DenyReasonCode.BINDING_FAILED]: {
    user: 'Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Request binding verification failed — generic binding error.',
  },
  [DenyReasonCode.NONCE_REPLAY]: {
    user: 'Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Nonce already consumed — replay attack detected.',
  },
  [DenyReasonCode.HASH_MISMATCH]: {
    user: 'Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Canonical request hash does not match expected value.',
  },
  [DenyReasonCode.AUDIENCE_MISMATCH]: {
    user: 'Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'DecisionCapsule audience does not match expected wallet app ID.',
  },
  [DenyReasonCode.BINDING_EXPIRED]: {
    user: 'Die Anfrage ist abgelaufen. Bitte starte den Vorgang neu.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Request timestamp outside acceptable skew window.',
  },
  [DenyReasonCode.DOWNGRADE_ATTACK]: {
    user: 'Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Capability downgrade rejected — requested profile disables mutually supported security features.',
  },

  // --- Crypto ---
  [DenyReasonCode.CRYPTO_VERIFY_FAILED]: {
    user: 'Sicherheitsprüfung fehlgeschlagen.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Cryptographic proof/signature verification failed.',
  },
  [DenyReasonCode.UNSUPPORTED_ALGORITHM]: {
    user: 'Nicht unterstützter Sicherheitsstandard.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Algorithm not in allowed algorithm set.',
  },
  [DenyReasonCode.KEY_STATUS_INVALID]: {
    user: 'Sicherheitsschlüssel ungültig.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Signing key revoked or status invalid.',
  },

  // --- Delegation ---
  [DenyReasonCode.AGENT_NOT_AUTHORIZED]: {
    user: 'Diese automatische Aktion ist nicht erlaubt.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Agent DID not in delegationRules.allowed_agent_dids.',
  },
  [DenyReasonCode.AGENT_LIMIT_EXCEEDED]: {
    user: 'Zu viele Daten für eine automatische Freigabe.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Agent request exceeds max_claims_per_request delegation limit.',
  },

  // --- Rate Limiting ---
  [DenyReasonCode.RATE_LIMIT_EXCEEDED]: {
    user: 'Zu viele Anfragen. Bitte warte einen Moment.',
    verifier: VERIFIER_BUCKET_RATE,
    audit: 'Verifier exceeded rate limit: >10 requests per 60s window.',
  },

  // --- Consent / Presence ---
  [DenyReasonCode.CONSENT_REQUIRED]: {
    user: 'Deine Zustimmung wird benötigt.',
    verifier: VERIFIER_BUCKET_USER_ACTION,
    audit: 'Policy rule requires explicit user consent (requiresUserConsent=true).',
  },
  [DenyReasonCode.PRESENCE_REQUIRED]: {
    user: 'Biometrische Bestätigung erforderlich. Bitte bestätige erneut.',
    verifier: VERIFIER_BUCKET_USER_ACTION,
    audit: 'Presence proof required — user did not interact with authenticator within challenge window (WebAuthn timeout) or accessibility/high-risk prompt.',
  },
  [DenyReasonCode.REAUTH_REQUIRED]: {
    user: 'Erneute Authentifizierung erforderlich. Bitte melde dich neu an.',
    verifier: VERIFIER_BUCKET_USER_ACTION,
    audit: 'Re-authentication required — session expired or WebAuthn challenge not found (consumed/lost). Full re-auth needed.',
  },

  // --- Infrastructure ---
  [DenyReasonCode.STATUS_SOURCE_UNAVAILABLE]: {
    user: 'Ein externer Dienst ist nicht erreichbar. Bitte versuche es später.',
    verifier: VERIFIER_BUCKET_INFRA,
    audit: 'Status source (revocation list, DID resolver) unavailable or timed out.',
  },
  [DenyReasonCode.RESOLVER_QUORUM_FAILED]: {
    user: 'Sicherheitsprüfung konnte nicht abgeschlossen werden.',
    verifier: VERIFIER_BUCKET_INFRA,
    audit: 'Multi-resolver quorum not reached — inconsistent key resolution.',
  },
  [DenyReasonCode.JURISDICTION_INCOMPATIBLE]: {
    user: 'Dieser Dienst ist in deiner Region nicht verfügbar.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Jurisdiction mismatch between requester runtime and policy requirements.',
  },

  // --- Conflict Resolution ---
  [DenyReasonCode.CONFLICT_DENY_WINS]: {
    user: 'Eine Sicherheitsregel blockiert diese Anfrage.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Multiple rules matched; at least one produced DENY — deny-wins applied.',
  },

  // --- Catch-all ---
  [DenyReasonCode.INTERNAL_SAFE_FAILURE]: {
    user: 'Ein interner Fehler ist aufgetreten. Bitte versuche es später.',
    verifier: VERIFIER_BUCKET_GENERIC,
    audit: 'Internal error caught and handled fail-closed.',
  },
};

/**
 * Get audience-specific message for a deny code.
 * Falls back to INTERNAL_SAFE_FAILURE for unknown codes (fail-closed).
 */
export function getDenyMessage(
  code: DenyReasonCode | string,
  audience: 'user' | 'verifier' | 'audit'
): string {
  const entry = DENY_REASON_CATALOG[code as DenyReasonCode];
  if (!entry) {
    // Unknown code → fail-closed, return generic
    return DENY_REASON_CATALOG[DenyReasonCode.INTERNAL_SAFE_FAILURE][audience];
  }
  return entry[audience];
}

/**
 * Get the verifier-facing message for ANY deny code.
 * This is the anti-oracle surface: verifiers see only bucket messages.
 */
export function getVerifierDenyMessage(code: DenyReasonCode | string): string {
  return getDenyMessage(code, 'verifier');
}
