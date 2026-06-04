/**
 * Runtime identifiers shared by AskMI demo apps and protocol packages.
 *
 * These are not security policy by themselves; they keep demo contracts,
 * tests, deep links, and verifier flows from drifting after rebrands.
 */

export const ASKMI_DEMO = {
  issuerUri: 'https://issuer.askmi.demo',
  issuerBaseUrl: 'http://localhost:3005',
  trustListUrl: 'http://localhost:3005/v1/eudi-lotl.json',
  statusListUri: 'http://localhost:3005/status-list/1',
  verifierDid: 'did:askmi:verifier-liquor-store',
  walletAudience: 'askmi-wallet-pwa',
} as const;

export const ASKMI_ENV = {
  testMode: 'ASKMI_TEST_MODE',
  legacyTestMode: 'MITCH_TEST_MODE',
  tslUrl: 'ASKMI_TSL_URL',
  legacyTslUrl: 'MITCH_TSL_URL',
} as const;

export const ASKMI_STORAGE_KEYS = {
  walletPolicy: 'askmi_user_policy',
  passkeyDb: 'askmi_passkey_db',
  passkeyRegistration: 'askmi_passkey_registration',
  identityKeyRegistration: 'askmi_identity_key_registration',
  webauthnSession: 'askmi_webauthn_session',
  policyManifestDocument: '__askmi_policy_manifest_v1',
} as const;

export const ASKMI_SCENARIO_IDS = [
  'liquor-store',
  'doctor-login',
  'ehds-er',
  'pharmacy',
  'revoked',
] as const;

export type AskmiScenarioId = (typeof ASKMI_SCENARIO_IDS)[number];

export const ASKMI_SCENARIO_VCT: Record<AskmiScenarioId, string> = {
  'liquor-store': 'https://askmi.demo/vct/age-credential',
  'doctor-login': 'https://askmi.demo/vct/professional-identity',
  'ehds-er': 'https://askmi.demo/vct/patient-summary',
  pharmacy: 'https://askmi.demo/vct/prescription',
  revoked: 'https://askmi.demo/vct/age-credential',
};

/**
 * Canonical demo-scenario claim fixtures (single source of truth).
 *
 * These are the underlying credential claims a simulated holder presents in each
 * demo scenario. Both the wallet PWA fixture and the verifier-demo backend derive
 * their `SCENARIO_CLAIMS` from this object so the two cannot drift apart.
 *
 * Key conventions:
 * - Holder-domain key names are used here (`birthDate`). The OID4VP/protocol layer
 *   uses `dateOfBirth`; the verifier-demo backend aliases `birthDate -> dateOfBirth`
 *   at that boundary, mirroring the wallet's existing protocol mapping. Do NOT
 *   rename these to protocol keys — the layering is intentional.
 * - Redaction placeholders (e.g. `salary: 'redacted'`) are the claim values that
 *   actually get disclosed/withheld in the flow. Display-only copy (e.g. the
 *   verifier frontend's `'€ [redacted]'`) is intentionally NOT generalized here.
 */
export const ASKMI_SCENARIO_CLAIMS: Record<AskmiScenarioId, Record<string, unknown>> = {
  'liquor-store': {
    age: 24,
    birthDate: '2000-01-01',
    name: 'Max Mustermann',
    address: 'Zirl, AT',
    nationalId: 'AT-123456',
  },
  'doctor-login': {
    age: 35,
    role: 'Surgeon',
    licenseId: 'MED-998877',
    employer: 'St. Mary Hospital',
    salary: 'redacted',
    homeAddress: 'redacted',
  },
  'ehds-er': {
    bloodGroup: 'A+',
    allergies: 'Penicillin, Cashew nuts',
    emergencyContacts: 'Mother: +49-151-555-0100',
    activeProblems: 'Asthma',
    diagnosis: '[full history]',
    geneticData: '[genetic profile]',
    insuranceId: 'INS-redacted',
  },
  pharmacy: {
    medication: 'Amoxicillin 500mg',
    dosageInstruction: '1 tablet every 8 hours',
    refillsRemaining: 2,
    diagnosis: '[prescribing diagnosis]',
    insuranceId: 'INS-redacted',
    geneticData: '[genetic markers]',
  },
  revoked: { age: 24 },
};
