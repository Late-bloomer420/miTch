/**
 * DemoPolicy.ts
 *
 * Das User-Manifest für den Demo-Flow.
 * Wird von WalletService als DEFAULT_POLICY geladen und in
 * localStoreShim persistiert. User-Änderungen (PolicyEditor) werden
 * darüber gemergt — diese Datei ist nur der "factory default".
 *
 * Regel-Logik:
 *   - requiresUserConsent: true  → PROMPT (User muss aktiv zustimmen)
 *   - requiresPresence: true     → PROMPT + WebAuthn-Ceremony (biometric bind)
 *   - provenClaims only          → ZKP-Nachweis, niemals Rohdaten
 *   - deniedClaims               → hart blockiert, engine wirft DENY
 */

import { PolicyManifest } from '@mitch/shared-types';

export const DEMO_POLICY: PolicyManifest = {
  version: '1.2',

  globalSettings: {
    // Unbekannte Verifier → DENY (fail-closed)
    blockUnknownVerifiers: true,
    // Keine stillen Auto-Releases ohne User-Aktion
    requireConsentForAll: false, // Per-Regel geregelt, nicht global (Performance)
    defaultFreshnessDays: 365,
    strictVerifierBinding: false, // für localhost-Demo relaxed
    denySecondaryUse: false,                // Default: erlaubt, User entscheidet per Consent
    denySecondaryUseCountries: ['US'],      // Beispiel: US-Verifier dürfen keine Sekundärnutzung
  },

  trustedIssuers: [
    {
      did: 'did:example:gov-issuer',
      name: 'Government ID Issuer (Demo)',
      credentialTypes: ['AgeCredential'],
    },
    {
      did: 'did:example:st-mary-hospital',
      name: 'St. Mary Hospital (Demo)',
      credentialTypes: ['EmploymentCredential', 'DoctorLicense'],
    },
    {
      did: 'did:example:ehealth-authority',
      name: 'European Health Data Space (EHDS)',
      credentialTypes: ['PatientSummary', 'Prescription', 'HealthRecord'],
    },
  ],

  rules: [
    // ── Rule 1: Altersnachweis (Liquor Store / Tabak etc.) ─────────────────
    // ZKP only — kein Rohdatum, kein Name, keine ID
    // Auto-ALLOW: Nutzer hat einmalig Zustimmung gegeben → kein PROMPT mehr
    {
      id: 'rule-age-proof-01',
      context: 'Altersnachweis ≥18 für regulierten Kauf (Liquor, Tabak)',
      verifierPattern: 'did:mitch:verifier-liquor-store',
      allowedClaims: [],               // Keine Rohdaten
      provenClaims: ['age >= 18'],     // Nur Nachweis (ZKP)
      deniedClaims: ['birthDate', 'name', 'address', 'nationalId'],
      requiresUserConsent: false,      // ← ALLOW (einmalig akzeptiert)
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 365,
      priority: 10,
    },

    // ── Rule 2: Arzt-Portal Login (Multi-VC: Alter + Berufserlaubnis) ──────
    // Erfordert aktive Zustimmung (PROMPT), aber KEIN biometrisches Binding
    {
      id: 'rule-hospital-login-01',
      context: 'Arzt-Login: Identität (≥18) + Berufserlaubnis',
      verifierPattern: 'med-portal-login',
      allowedClaims: ['role', 'licenseId'],
      provenClaims: ['age >= 18'],
      deniedClaims: ['birthDate', 'salary', 'homeAddress'],
      requiresUserConsent: true,       // ← PROMPT
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 180,
      priority: 20,
    },

    // ── Rule 3: EHDS Notaufnahme (Gesundheitsdaten) ────────────────────────
    // Sensibelste Daten: PROMPT + Presence (biometric bind) PFLICHT
    // Entspricht Layer 2 — Commercialization absolut verboten
    {
      id: 'rule-ehds-emergency-01',
      context: 'EHDS Notaufnahme: Blutgruppe, Allergien, Notfallkontakte',
      verifierPattern: 'hospital-*-er-*',   // Wildcard: alle ER-Verifier
      allowedClaims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
      provenClaims: [],
      deniedClaims: ['insuranceId', 'financialData', 'geneticData'],
      requiresUserConsent: true,       // ← PROMPT
      requiresPresence: true,          // ← WebAuthn PFLICHT (Layer 2)
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 730,       // 2 Jahre für Notfalldaten
      priority: 100,                   // Höchste Prio
    },

    // ── Rule 4: Sekundärnutzung — Forschungsinstitut ──────────────────────
    // Anonymisiertes Subset, kein biometrisches Binding, aber User-Consent PFLICHT
    {
      id: 'rule-research-secondary-01',
      context: 'Secondary Use — Research Institute',
      verifierPattern: '*-research-*',
      usagePurpose: 'researchSecondary',
      allowedClaims: ['bloodGroup', 'allergies'],          // anonymisiertes Subset
      provenClaims: [],
      deniedClaims: ['emergencyContacts', 'insuranceId', 'geneticData', 'name', 'address'],
      requiresUserConsent: true,       // ← PROMPT
      requiresPresence: false,
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 730,
      priority: 40,
    },

    // ── Rule 5: Apotheke / Rezept ──────────────────────────────────────────
    {
      id: 'rule-pharmacy-01',
      context: 'Rezept-Einlösung: Medikation, Dosierung',
      verifierPattern: 'pharmacy-*',
      allowedClaims: ['medication', 'dosageInstruction', 'refillsRemaining'],
      provenClaims: [],
      deniedClaims: ['diagnosis', 'geneticData', 'insuranceId'],
      requiresUserConsent: true,       // ← PROMPT
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 30,        // Rezepte sind kurzlebig
      priority: 50,
    },
  ],
};

// ── Type-Erweiterung für requiresPresence ────────────────────────────────────
//
// PolicyRule in @mitch/shared-types kennt `requiresPresence` noch nicht.
// Bis das Feld dort offiziell ergänzt ist, kannst du den Typ lokal erweitern:
//
//   declare module '@mitch/shared-types' {
//     interface PolicyRule {
//       requiresPresence?: boolean;
//     }
//   }
//
// Empfehlung: Das Feld direkt in shared-types/src/policy.ts ergänzen (siehe Schritt 1b unten).
