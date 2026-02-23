export interface VerificationClaim {
  type: "predicate";
  name: string;
  value: string | number | boolean;
}

export interface VerificationRequestV0 {
  version: "v0";
  requestId: string;
  rp: {
    id: string;
    audience: string;
    jurisdiction?: string;
  };
  purpose: string;
  claims: VerificationClaim[];
  proofBundle: ProofBundleV0;
  binding: {
    nonce: string;
    requestHash: string;
    expiresAt: string;
  };
  policyRef: string;
  meta?: {
    channel?: string;
    traceLevel?: "minimal" | "debug";
    reAuthRecent?: boolean;
    reAuthMethod?: "webauthn" | "other";
    reAuthAssertion?: string;
    reAuthChallenge?: string;
    reAuthIssuedAt?: string;
    reAuthRpId?: string;
    reAuthOrigin?: string;
  };
}

export interface VerificationResponseV0 {
  version: "v0";
  requestId: string;
  decision: "ALLOW" | "DENY";
  decisionCode: string;
  claimsSatisfied: Array<{ name: string; value: string | number | boolean }>;
  receiptRef: string;
  verifiedAt: string;
}

export interface ProofBundleV0 {
  format: string;
  proof: string;
  disclosures?: string[];
  keyId?: string;
  credentialId?: string;
  credentialStatus?: {
    type: "StatusList2021Entry";
    statusListCredential: string;
    statusListIndex: string;
  };
  alg?: string;
}
