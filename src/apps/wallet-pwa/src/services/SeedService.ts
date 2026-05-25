import { SecureStorage } from '@mitch/secure-storage';
import { encode as mdocEncode } from '@mitch/mdoc';

// ─── mdoc base64 helpers ──────────────────────────────────────────────────
function uint8ArrayToBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary);
}

export const SEED_CREDENTIAL = {
  id: 'vc-age-789',
  issuer: 'did:example:gov-issuer',
  type: ['VerifiableCredential', 'AgeCredential'],
  issuedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['birthDate', 'age'],
  payload: {
    birthDate: '2000-01-01',
    age: 24, // Raw PII in Secure Storage (demo only)
  },
};

export const MALICIOUS_CREDENTIAL = {
  id: 'vc-fake-999',
  issuer: 'did:example:malicious-hacker',
  type: ['VerifiableCredential', 'AgeCredential'],
  issuedAt: new Date().toISOString(),
  claims: ['age'],
  payload: {
    age: 25,
  },
};

export const EMPLOYMENT_CREDENTIAL = {
  id: 'vc-emp-456',
  issuer: 'did:example:st-mary-hospital',
  type: ['VerifiableCredential', 'EmploymentCredential'],
  issuedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['employer', 'role', 'licenseId'],
  payload: {
    employer: 'St. Mary Hospital',
    role: 'Surgeon',
    licenseId: 'MED-998877',
  },
};

// EHDS Sample Credentials defined here for seeding
export const EHDS_PATIENT_SUMMARY = {
  id: 'vc-ehds-summary-001',
  issuer: 'did:example:ehealth-authority',
  type: ['VerifiableCredential', 'HealthRecord', 'PatientSummary'], // Polymorphic types
  issuedAt: new Date().toISOString(),
  claims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
  payload: {
    resourceType: 'PatientSummary',
    status: 'final',
    effectiveDateTime: new Date().toISOString(),
    performer: { display: 'Seven Bridges Genomics', reference: 'did:example:ehealth-authority' },
    content: {
      bloodGroup: 'A+',
      allergies: [
        { code: '91936005', display: 'Penicillin', criticality: 'high' },
        { code: '227493005', display: 'Cashew nuts', criticality: 'low' },
      ],
      activeProblems: ['Asthma'],
      emergencyContacts: [{ relation: 'Mother', phone: '+49-151-555-0100' }],
    },
  },
};

export const EHDS_PRESCRIPTION = {
  id: 'vc-ehds-rx-999',
  issuer: 'did:example:ehealth-authority',
  type: ['VerifiableCredential', 'HealthRecord', 'Prescription'],
  issuedAt: new Date().toISOString(),
  claims: ['medication', 'dosageInstruction', 'refillsRemaining'],
  payload: {
    resourceType: 'Prescription',
    status: 'final',
    effectiveDateTime: new Date().toISOString(),
    performer: { display: 'Dr. House', reference: 'did:example:st-mary-hospital' },
    content: {
      medication: { code: '372665008', display: 'Amoxicillin 500mg' },
      dosageInstruction: 'Take 1 tablet every 8 hours for 7 days',
      quantity: 21,
      refillsRemaining: 0,
    },
  },
};

// ISO 18013-5 mdoc mDL Seed Credential
export const MDOC_MDL_CREDENTIAL = {
  id: 'mdoc-mdl-001',
  issuer: 'did:example:gov-transport',
  docType: 'org.iso.18013.5.1.mDL',
  claims: [
    'family_name',
    'given_name',
    'birth_date',
    'age_over_18',
    'age_over_21',
    'issuing_country',
  ],
};

export class SeedService {
  /**
   * Seeding initial minimized and progressive demo credentials into secure storage.
   */
  static async ensureSeeded(storage: SecureStorage): Promise<void> {
    const metas = await storage.getAllMetadata();

    // 1. Initial Seed (Ensure Core Credential exists)
    const seedMeta = metas.find((m) => m.id === SEED_CREDENTIAL.id);
    if (!seedMeta) {
      console.log('Seeding initial minimized credentials...');
      await storage.save(SEED_CREDENTIAL.id, SEED_CREDENTIAL.payload, {
        issuer: SEED_CREDENTIAL.issuer,
        type: SEED_CREDENTIAL.type,
        claims: SEED_CREDENTIAL.claims,
        issuedAt: SEED_CREDENTIAL.issuedAt,
      });
    } else {
      try {
        const existing = await storage.load<Record<string, unknown>>(SEED_CREDENTIAL.id);
        if (existing && !('birthDate' in existing)) {
          await storage.save(SEED_CREDENTIAL.id, SEED_CREDENTIAL.payload, {
            issuer: SEED_CREDENTIAL.issuer,
            type: SEED_CREDENTIAL.type,
            claims: SEED_CREDENTIAL.claims,
            issuedAt: SEED_CREDENTIAL.issuedAt,
          });
          console.log('Updated age credential to include birthDate for ZKP predicates.');
        }
      } catch (e) {
        console.warn('Seed check failed for age credential.', e);
      }
    }

    // 2. Progressive Seeding
    if (!metas.find((m) => m.id === EMPLOYMENT_CREDENTIAL.id)) {
      console.log('Seeding Employment Credential...');
      await storage.save(EMPLOYMENT_CREDENTIAL.id, EMPLOYMENT_CREDENTIAL.payload, {
        issuer: EMPLOYMENT_CREDENTIAL.issuer,
        type: EMPLOYMENT_CREDENTIAL.type,
        claims: EMPLOYMENT_CREDENTIAL.claims,
        issuedAt: EMPLOYMENT_CREDENTIAL.issuedAt,
      });
    }

    // 3. EHDS Credentials (If missing)
    if (!metas.find((m) => m.id === EHDS_PATIENT_SUMMARY.id)) {
      console.log('Seeding EHDS Patient Summary...');
      const summaryPayload = {
        ...EHDS_PATIENT_SUMMARY.payload,
        ...EHDS_PATIENT_SUMMARY.payload.content,
      };
      await storage.save(EHDS_PATIENT_SUMMARY.id, summaryPayload, {
        issuer: EHDS_PATIENT_SUMMARY.issuer,
        type: EHDS_PATIENT_SUMMARY.type,
        claims: EHDS_PATIENT_SUMMARY.claims,
        issuedAt: EHDS_PATIENT_SUMMARY.issuedAt,
      });
    }

    if (!metas.find((m) => m.id === EHDS_PRESCRIPTION.id)) {
      console.log('Seeding EHDS Prescription...');
      const rxPayload = { ...EHDS_PRESCRIPTION.payload, ...EHDS_PRESCRIPTION.payload.content };
      await storage.save(EHDS_PRESCRIPTION.id, rxPayload, {
        issuer: EHDS_PRESCRIPTION.issuer,
        type: EHDS_PRESCRIPTION.type,
        claims: EHDS_PRESCRIPTION.claims,
        issuedAt: EHDS_PRESCRIPTION.issuedAt,
      });
    }

    // 4. mdoc mDL Credential (ISO 18013-5)
    if (!metas.find((m) => m.id === MDOC_MDL_CREDENTIAL.id)) {
      console.log('Seeding mdoc mDL Credential...');
      const mdocItems = [
        {
          digestID: 0,
          random: crypto.getRandomValues(new Uint8Array(16)),
          elementIdentifier: 'family_name',
          elementValue: 'Mustermann',
        },
        {
          digestID: 1,
          random: crypto.getRandomValues(new Uint8Array(16)),
          elementIdentifier: 'given_name',
          elementValue: 'Erika',
        },
        {
          digestID: 2,
          random: crypto.getRandomValues(new Uint8Array(16)),
          elementIdentifier: 'birth_date',
          elementValue: '1990-05-15',
        },
        {
          digestID: 3,
          random: crypto.getRandomValues(new Uint8Array(16)),
          elementIdentifier: 'age_over_18',
          elementValue: true,
        },
        {
          digestID: 4,
          random: crypto.getRandomValues(new Uint8Array(16)),
          elementIdentifier: 'age_over_21',
          elementValue: true,
        },
        {
          digestID: 5,
          random: crypto.getRandomValues(new Uint8Array(16)),
          elementIdentifier: 'issuing_country',
          elementValue: 'DE',
        },
      ];
      const mdocCbor = mdocEncode({
        nameSpaces: new Map([['org.iso.18013.5.1', mdocItems]]),
      });
      const mdocPayload = {
        _mdoc: true,
        docType: MDOC_MDL_CREDENTIAL.docType,
        cborBase64: uint8ArrayToBase64(mdocCbor),
      };
      await storage.save(MDOC_MDL_CREDENTIAL.id, mdocPayload, {
        issuer: MDOC_MDL_CREDENTIAL.issuer,
        type: ['VerifiableCredential', MDOC_MDL_CREDENTIAL.docType],
        issuedAt: new Date().toISOString(),
        claims: MDOC_MDL_CREDENTIAL.claims,
        format: 'mso_mdoc',
      });
    }
  }
}
