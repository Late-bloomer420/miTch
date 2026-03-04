export type ScenarioId = 'liquor-store' | 'doctor-login' | 'ehds-er' | 'pharmacy';

export interface CredentialField {
  key: string;
  value: string;
  blocked: boolean;
}

export interface WalletCredential {
  type: string;
  issuer: string;
  fields: CredentialField[];
}

export interface VerifierClaim {
  key: string;
  value: string;
  isProof: boolean;
}

export interface ScenarioDefinition {
  id: ScenarioId;
  label: string;
  emoji: string;
  verdict: 'ALLOW' | 'PROMPT' | 'PROMPT+BIOMETRIC';
  walletCredentials: WalletCredential[];
  verifierReceives: VerifierClaim[];
  blocked: string[];
  detectionKeys: string[];
}

export const SCENARIOS: Record<ScenarioId, ScenarioDefinition> = {
  'liquor-store': {
    id: 'liquor-store',
    label: 'Liquor Store',
    emoji: '🍺',
    verdict: 'ALLOW',
    detectionKeys: ['isOver18', 'age_gte_18'],
    walletCredentials: [{
      type: 'AgeCredential (GovID)',
      issuer: 'did:example:gov-issuer',
      fields: [
        { key: 'age',       value: '24',              blocked: false },
        { key: 'birthDate', value: '2000-01-01',      blocked: true },
        { key: 'name',      value: 'Max Mustermann',  blocked: true },
        { key: 'address',   value: 'Zirl, AT',        blocked: true },
        { key: 'nationalId',value: 'AT-123456',       blocked: true },
      ],
    }],
    verifierReceives: [
      { key: 'age ≥ 18', value: 'true', isProof: true },
    ],
    blocked: ['birthDate', 'name', 'address', 'nationalId'],
  },

  'doctor-login': {
    id: 'doctor-login',
    label: 'Doctor Login',
    emoji: '🏥',
    verdict: 'PROMPT',
    detectionKeys: ['licenseId', 'role'],
    walletCredentials: [
      {
        type: 'AgeCredential (GovID)',
        issuer: 'did:example:gov-issuer',
        fields: [
          { key: 'age',       value: '24',         blocked: false },
          { key: 'birthDate', value: '2000-01-01', blocked: true },
        ],
      },
      {
        type: 'EmploymentCredential (St. Mary)',
        issuer: 'did:example:st-mary-hospital',
        fields: [
          { key: 'role',        value: 'Surgeon',           blocked: false },
          { key: 'licenseId',   value: 'MED-998877',        blocked: false },
          { key: 'employer',    value: 'St. Mary Hospital', blocked: true },
          { key: 'salary',      value: '€ [redacted]',      blocked: true },
          { key: 'homeAddress', value: '[redacted]',         blocked: true },
        ],
      },
    ],
    verifierReceives: [
      { key: 'age ≥ 18',  value: 'true',      isProof: true },
      { key: 'role',       value: 'Surgeon',   isProof: false },
      { key: 'licenseId',  value: 'MED-998877', isProof: false },
    ],
    blocked: ['birthDate', 'employer', 'salary', 'homeAddress'],
  },

  'ehds-er': {
    id: 'ehds-er',
    label: 'EHDS Emergency',
    emoji: '🚑',
    verdict: 'PROMPT+BIOMETRIC',
    detectionKeys: ['bloodGroup', 'allergies'],
    walletCredentials: [{
      type: 'PatientSummary (EHDS)',
      issuer: 'did:example:ehealth-authority',
      fields: [
        { key: 'bloodGroup',        value: 'A+',                       blocked: false },
        { key: 'allergies',         value: 'Penicillin, Cashew nuts',  blocked: false },
        { key: 'emergencyContacts', value: 'Mother: +49-151-555-0100', blocked: false },
        { key: 'activeProblems',    value: 'Asthma',                   blocked: false },
        { key: 'diagnosis',         value: '[full history]',           blocked: true },
        { key: 'geneticData',       value: '[genetic profile]',        blocked: true },
        { key: 'insuranceId',       value: 'INS-[redacted]',          blocked: true },
      ],
    }],
    verifierReceives: [
      { key: 'bloodGroup',        value: 'A+',                       isProof: false },
      { key: 'allergies',         value: 'Penicillin, Cashew nuts',  isProof: false },
      { key: 'emergencyContacts', value: 'Mother: +49-151-555-0100', isProof: false },
    ],
    blocked: ['diagnosis', 'geneticData', 'insuranceId'],
  },

  'pharmacy': {
    id: 'pharmacy',
    label: 'Pharmacy',
    emoji: '💊',
    verdict: 'PROMPT',
    detectionKeys: ['medication', 'dosageInstruction'],
    walletCredentials: [{
      type: 'Prescription (EHDS)',
      issuer: 'did:example:ehealth-authority',
      fields: [
        { key: 'medication',        value: 'Amoxicillin 500mg',       blocked: false },
        { key: 'dosageInstruction', value: '1 tablet every 8 hours',  blocked: false },
        { key: 'refillsRemaining',  value: '2',                       blocked: false },
        { key: 'diagnosis',         value: '[prescribing diagnosis]', blocked: true },
        { key: 'insuranceId',       value: 'INS-[redacted]',          blocked: true },
        { key: 'geneticData',       value: '[genetic markers]',       blocked: true },
      ],
    }],
    verifierReceives: [
      { key: 'medication',        value: 'Amoxicillin 500mg',      isProof: false },
      { key: 'dosageInstruction', value: '1 tablet every 8 hours', isProof: false },
      { key: 'refillsRemaining',  value: '2',                      isProof: false },
    ],
    blocked: ['diagnosis', 'insuranceId', 'geneticData'],
  },
};

export const SCENARIO_ORDER: ScenarioId[] = [
  'liquor-store', 'doctor-login', 'ehds-er', 'pharmacy',
];

export function detectScenario(
  proofPayload: Record<string, unknown>
): ScenarioId | null {
  if ('bloodGroup' in proofPayload || 'allergies' in proofPayload) return 'ehds-er';
  if ('medication' in proofPayload || 'dosageInstruction' in proofPayload) return 'pharmacy';
  if ('licenseId' in proofPayload || 'role' in proofPayload) return 'doctor-login';
  if ('isOver18' in proofPayload || 'age_gte_18' in proofPayload) return 'liquor-store';
  return null;
}
