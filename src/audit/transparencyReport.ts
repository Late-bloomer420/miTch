/**
 * Transparency Report — GDPR Art. 13/14
 * 
 * Machine-readable transparency information.
 * Used by the landing page to show users exactly what miTch does and doesn't do.
 */

export interface TransparencyReport {
  version: "v0";
  generatedAt: string;
  
  dataController: {
    name: string;
    contact: string;
    dpo?: string;                  // Data Protection Officer
  };
  
  whatWeProcess: {
    category: string;
    purpose: string;
    legalBasis: string;
    retention: string;
  }[];
  
  whatWeNeverProcess: string[];
  
  whatWeLog: {
    item: string;
    detail: string;
  }[];
  
  whatWeNeverLog: string[];
  
  userRights: {
    right: string;
    gdprArticle: string;
    howToExercise: string;
    mitchImplementation: string;
  }[];
  
  technicalSafeguards: {
    measure: string;
    description: string;
  }[];
}

export function generateTransparencyReport(controllerName: string, controllerContact: string): TransparencyReport {
  return {
    version: "v0",
    generatedAt: new Date().toISOString(),
    
    dataController: {
      name: controllerName,
      contact: controllerContact,
    },
    
    whatWeProcess: [
      {
        category: "Age predicates (e.g., over_18: true/false)",
        purpose: "Age verification for legal compliance",
        legalBasis: "GDPR Art. 6(1)(c) — legal obligation / Art. 6(1)(a) — consent",
        retention: "Crypto-shredded immediately after credential issuance. Predicate only in signed credential (held by user).",
      },
      {
        category: "Email verification status",
        purpose: "Account recovery, communication verification",
        legalBasis: "GDPR Art. 6(1)(a) — consent",
        retention: "Crypto-shredded after credential issuance.",
      },
      {
        category: "Jurisdiction (country code)",
        purpose: "Legal compliance routing",
        legalBasis: "GDPR Art. 6(1)(c) — legal obligation",
        retention: "Crypto-shredded after credential issuance.",
      },
    ],
    
    whatWeNeverProcess: [
      "Full name",
      "Date of birth (only age predicates like over_18)",
      "Home address",
      "Phone number",
      "Government ID numbers",
      "Biometric data",
      "Financial account details",
      "Browsing history",
      "Location data",
      "Device identifiers",
    ],
    
    whatWeLog: [
      { item: "Aggregate verification count", detail: "e.g., '47 verifications this hour' — no identifiers" },
      { item: "Error rates by type", detail: "e.g., '3 signature failures' — no request details" },
      { item: "System health metrics", detail: "Uptime, memory, response latency percentiles" },
    ],
    
    whatWeNeverLog: [
      "IP addresses (not even hashed)",
      "User agents or device information",
      "Request or response bodies",
      "Credential IDs or key IDs",
      "Which verifier was contacted",
      "Per-request timestamps (only hourly aggregates)",
      "Which claims were shared or declined",
      "User identity in any form",
    ],
    
    userRights: [
      {
        right: "Right of access",
        gdprArticle: "Art. 15",
        howToExercise: "Open your wallet — all your data is there",
        mitchImplementation: "All data stored locally on user's device. Full visibility in wallet UI.",
      },
      {
        right: "Right to erasure",
        gdprArticle: "Art. 17",
        howToExercise: "Delete credential in wallet, or it auto-destructs via crypto-shredding",
        mitchImplementation: "Crypto-shredding: encryption key destroyed = data mathematically irrecoverable. Exceeds Art. 17 requirements.",
      },
      {
        right: "Right to data portability",
        gdprArticle: "Art. 20",
        howToExercise: "Export consent receipts from wallet (JSON/PDF)",
        mitchImplementation: "One-tap export of all consent history in standard format.",
      },
      {
        right: "Right to withdraw consent",
        gdprArticle: "Art. 7(3)",
        howToExercise: "Revoke any consent in the wallet's consent log",
        mitchImplementation: "Per-verifier consent revocation. Remembered approvals can be revoked anytime.",
      },
      {
        right: "Right to object",
        gdprArticle: "Art. 21",
        howToExercise: "Decline any verification request, block specific verifiers",
        mitchImplementation: "Every request shows equal-weight Approve/Decline. Verifier blocking available.",
      },
    ],
    
    technicalSafeguards: [
      { measure: "Selective disclosure (SD-JWT)", description: "Share only the specific claims needed. Verifier never sees other data." },
      { measure: "Crypto-shredding", description: "Raw data encrypted with ephemeral keys. Keys destroyed after use. Data irrecoverable." },
      { measure: "Response padding", description: "All responses padded to fixed 4KB. Network observers can't infer content from size." },
      { measure: "Timing jitter", description: "Random 50-200ms delay on all responses. Prevents timing correlation." },
      { measure: "Per-session identifiers", description: "Each presentation uses a unique derived ID. Verifiers can't correlate across sessions." },
      { measure: "StatusList2021 revocation", description: "Revocation via public bitstring. Issuer can't tell which credential was checked." },
      { measure: "Identical decline responses", description: "Declined and missing credentials produce identical responses. Verifier can't distinguish." },
      { measure: "Tamper-evident audit chain", description: "All actions logged in hash-chain. Tampering breaks the chain and is detectable." },
      { measure: "No server-side PII storage", description: "miTch infrastructure stores zero personal data. All PII stays on user's device." },
    ],
  };
}
