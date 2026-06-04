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
