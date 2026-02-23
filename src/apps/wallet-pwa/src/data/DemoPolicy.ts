import { PolicyManifest } from '@mitch/shared-types';

export const DEMO_POLICY: PolicyManifest = {
    version: "1.0",
    globalSettings: {
        requireConsentForAll: true,
        blockUnknownVerifiers: true
    },
    trustedIssuers: [
        {
            did: "did:example:gov-issuer",
            name: "Government ID Issuer",
            credentialTypes: ["AgeCredential"]
        },
        {
            did: "did:example:st-mary-hospital",
            name: "St. Mary Hospital",
            credentialTypes: ["EmploymentCredential", "DoctorLicense"]
        },
        {
            did: "did:example:ehealth-authority", // T-30: EHDS
            name: "European Health Data Space",
            credentialTypes: ["PatientSummary", "Prescription", "HealthRecord"]
        }
    ],
    rules: [
        {
            id: "rule-liquor-store-01",
            context: "Allow Age Verification for Liquor Store",
            verifierPattern: "did:mitch:verifier-liquor-store", // Exact match
            allowedClaims: [], // Zero-Knowledge: No raw attributes
            provenClaims: ["age >= 18"], // Only proof result
            priority: 10
        },
        {
            id: "rule-hospital-er-01", // T-30a
            context: "Allow Emergency Access to Patient Summary",
            verifierPattern: "hospital-madrid-er-1",
            allowedClaims: ["bloodGroup", "allergies", "activeProblems", "emergencyContacts"],
            provenClaims: [],
            priority: 100 // Emergency Priority
        },
        {
            id: "rule-pharmacy-01", // T-30b
            context: "Allow Prescription Fulfillment",
            verifierPattern: "pharmacy-berlin-center",
            allowedClaims: ["medication", "dosageInstruction", "refillsRemaining"],
            provenClaims: [],
            priority: 50
        }
    ]
};
