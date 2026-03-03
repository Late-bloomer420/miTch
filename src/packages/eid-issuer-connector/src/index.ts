/**
 * @package @mitch/eid-issuer-connector
 * @description Connector for German eID issuers — High-Fidelity Simulator
 *
 * Supports:
 * - **simulator** (default): High-fidelity eID simulation with real crypto
 * - ausweisapp2: (STUB) Real AusweisApp2 SDK integration
 * - eidas: (STUB) eIDAS cross-border SAML connector
 * - mock: Legacy basic mock (backward compat)
 *
 * ## Simulator Fidelity
 * ✅ Real: ES256 signatures, SD-JWT VC format, did:web DID Document, age predicates
 * ❌ Simulated: PIN verification, smartcard interaction, certificate chain
 * See docs/specs/110_eID_Issuer_Simulator_Fidelity.md
 */

import type {
  EIDIssuanceRequest,
  EIDIssuanceResponse,
  EIDAttribute,
  AusweisApp2Config,
  EIDProtocolSession,
  EIDProtocolState,
  SDJWTVCPayload,
  EIDSimulatorConfig,
  SimulatorDIDDocument,
} from './types';
import { SignJWT, importJWK, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import type { JWK, KeyLike } from 'jose';
import { createHash, randomUUID, randomBytes } from 'crypto';

// ─── SD-JWT Helpers ─────────────────────────────────────────────────────────

/**
 * Create a base64url-encoded SD-JWT disclosure.
 * Format: base64url(salt + "~" + claimName + "~" + claimValue)
 */
function createDisclosure(salt: string, claimName: string, claimValue: unknown): string {
  const disclosureArray = [salt, claimName, claimValue];
  const json = JSON.stringify(disclosureArray);
  return Buffer.from(json).toString('base64url');
}

/**
 * Hash a disclosure for inclusion in _sd array.
 */
function hashDisclosure(disclosure: string): string {
  return createHash('sha256').update(disclosure).digest('base64url');
}

// ─── Simulated Citizen Data ─────────────────────────────────────────────────

/**
 * Simulated German citizen database.
 * In production, this data comes from the eID chip via AusweisApp2.
 */
const SIMULATED_CITIZENS: Record<string, Record<string, string>> = {
  default: {
    givenName: 'Max',
    familyName: 'Mustermann',
    dateOfBirth: '1990-01-15',
    placeOfBirth: 'Berlin',
    nationality: 'DE',
    streetAddress: 'Musterstraße 1',
    locality: 'Berlin',
    postalCode: '10115',
    country: 'DE',
    documentNumber: 'T22000001',
    documentExpiry: '2030-12-31',
  },
  minor: {
    givenName: 'Lisa',
    familyName: 'Mustermann',
    dateOfBirth: '2012-06-20',
    placeOfBirth: 'München',
    nationality: 'DE',
    streetAddress: 'Musterstraße 1',
    locality: 'München',
    postalCode: '80331',
    country: 'DE',
    documentNumber: 'T22000002',
    documentExpiry: '2028-06-20',
  },
};

// ─── EID Issuer Connector ───────────────────────────────────────────────────

export class EIDIssuerConnector {
  private mode: 'mock' | 'simulator' | 'ausweisapp2' | 'eidas';
  private issuerDID: string;
  private privateKey?: KeyLike;
  private publicKey?: KeyLike;
  private publicKeyJwk?: JWK;
  private simulatedDelayMs: number;
  private credentialValiditySec: number;
  private sessions = new Map<string, EIDProtocolSession>();

  constructor(
    mode: 'mock' | 'simulator' | 'ausweisapp2' | 'eidas' = 'simulator',
    config?: Partial<EIDSimulatorConfig>
  ) {
    this.mode = mode;
    this.issuerDID = config?.issuerDID ?? 'did:web:eid-simulator.mitch.local';
    this.simulatedDelayMs = config?.simulatedDelayMs ?? 0;
    this.credentialValiditySec = config?.credentialValiditySec ?? 365 * 24 * 60 * 60;
  }

  /**
   * Initialize the connector — generates ES256 keypair for signing.
   */
  async initialize(): Promise<void> {
    if (this.mode === 'mock' || this.mode === 'simulator') {
      const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      this.publicKeyJwk = await exportJWK(publicKey);
      // Add alg for DID Document
      this.publicKeyJwk.alg = 'ES256';
    } else {
      throw new Error(`Mode ${this.mode} not yet implemented`);
    }
  }

  // ─── DID Document ───────────────────────────────────────────────────────

  /**
   * Get the simulator's DID Document with published verification key.
   * In production, this would be hosted at the did:web URL.
   */
  getDIDDocument(): SimulatorDIDDocument {
    if (!this.publicKeyJwk) {
      throw new Error('Connector not initialized');
    }
    const keyId = `${this.issuerDID}#key-1`;
    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
      id: this.issuerDID,
      verificationMethod: [
        {
          id: keyId,
          type: 'JsonWebKey2020',
          controller: this.issuerDID,
          publicKeyJwk: this.publicKeyJwk as unknown as Record<string, unknown>,
        },
      ],
      assertionMethod: [keyId],
      authentication: [keyId],
    };
  }

  /**
   * Get the issuer's public key in JWK format (for external verification).
   */
  getPublicKeyJWK(): JWK {
    if (!this.publicKeyJwk) {
      throw new Error('Connector not initialized');
    }
    return { ...this.publicKeyJwk };
  }

  /**
   * Get the issuer DID.
   */
  getDID(): string {
    return this.issuerDID;
  }

  // ─── Issuance ─────────────────────────────────────────────────────────

  /**
   * Request credential issuance.
   * In simulator mode, runs the full simulated eID-Client protocol.
   */
  async requestIssuance(
    request: EIDIssuanceRequest,
    citizenProfile: string = 'default'
  ): Promise<EIDIssuanceResponse> {
    if (!request.userDID || !request.requestedAttributes?.length || !request.purpose) {
      throw new Error('Invalid issuance request: userDID, requestedAttributes, and purpose are required');
    }

    if (this.mode === 'simulator') {
      return this.simulatorIssuance(request, citizenProfile);
    } else if (this.mode === 'mock') {
      return this.legacyMockIssuance(request);
    } else if (this.mode === 'ausweisapp2') {
      throw new Error('AusweisApp2 integration not yet implemented');
    } else if (this.mode === 'eidas') {
      throw new Error('eIDAS integration not yet implemented');
    }
    throw new Error(`Unsupported mode: ${this.mode}`);
  }

  // ─── Simulator Protocol ───────────────────────────────────────────────

  /**
   * High-fidelity eID issuance simulation.
   * Models the real eID-Client protocol states without actual hardware.
   */
  private async simulatorIssuance(
    request: EIDIssuanceRequest,
    citizenProfile: string
  ): Promise<EIDIssuanceResponse> {
    if (!this.privateKey) {
      throw new Error('Simulator not initialized');
    }

    const citizenData = SIMULATED_CITIZENS[citizenProfile];
    if (!citizenData) {
      throw new Error(`Unknown citizen profile: ${citizenProfile}`);
    }

    // Create protocol session
    const session: EIDProtocolSession = {
      sessionId: randomUUID(),
      state: 'idle',
      request,
      createdAt: Date.now(),
    };
    this.sessions.set(session.sessionId, session);

    try {
      // Step 1: Generate TC Token (eID-Client protocol initiation)
      session.state = 'tc_token_generated';
      await this.simulateDelay();

      // Step 2: PIN entry (simulated — in production, user enters PIN on device)
      session.state = 'pin_requested';
      await this.simulateDelay();
      session.state = 'pin_entered';

      // Step 3: Card reading (simulated — in production, NFC/contact reader)
      session.state = 'card_reading';
      await this.simulateDelay();
      session.citizenData = citizenData;
      session.state = 'card_read_complete';

      // Step 4: Issue SD-JWT VC credential
      session.state = 'credential_issuing';
      const credential = await this.issueSDJWTVC(request, citizenData);

      session.state = 'complete';
      session.completedAt = Date.now();

      return credential;
    } catch (err) {
      session.state = 'error';
      session.error = err instanceof Error ? err.message : String(err);
      throw err;
    }
  }

  /**
   * Issue an SD-JWT VC credential with selective disclosure.
   * 
   * Structure: <issuer-signed-JWT>~<disclosure1>~<disclosure2>~...
   * Each disclosure is base64url([salt, claimName, claimValue])
   */
  private async issueSDJWTVC(
    request: EIDIssuanceRequest,
    citizenData: Record<string, string>
  ): Promise<EIDIssuanceResponse> {
    const now = Math.floor(Date.now() / 1000);
    const jti = `urn:uuid:${randomUUID()}`;
    const disclosures: string[] = [];
    const sdHashes: string[] = [];

    // Create disclosures for each requested attribute
    for (const attr of request.requestedAttributes) {
      if (!(attr in citizenData)) continue;
      const salt = randomBytes(16).toString('base64url');
      const disclosure = createDisclosure(salt, attr, citizenData[attr]);
      disclosures.push(disclosure);
      sdHashes.push(hashDisclosure(disclosure));
    }

    // Compute age predicate (isOver18) — always included if dateOfBirth is available
    const isOver18 = citizenData.dateOfBirth
      ? computeAge(new Date(citizenData.dateOfBirth)) >= 18
      : undefined;

    // Build SD-JWT payload
    const payload: SDJWTVCPayload = {
      iss: this.issuerDID,
      sub: request.userDID,
      iat: now,
      exp: now + this.credentialValiditySec,
      jti,
      vct: 'urn:eu:europa:ec:eudi:pid:1',
      _sd_alg: 'sha-256',
      _sd: sdHashes,
      // Non-disclosable claims (always visible)
      purpose: request.purpose,
    };

    // Add age predicate as non-disclosable claim if available
    if (isOver18 !== undefined) {
      (payload as any).age_over_18 = isOver18;
    }

    // Sign JWT part
    const jwt = await new SignJWT(payload as any)
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'vc+sd-jwt',
        kid: `${this.issuerDID}#key-1`,
      })
      .sign(this.privateKey!);

    // Assemble SD-JWT: <jwt>~<disclosure1>~<disclosure2>~
    const sdJwt = [jwt, ...disclosures, ''].join('~');

    return {
      credential: sdJwt,
      format: 'sd-jwt-vc',
      issuer: this.issuerDID,
      issuedAt: now * 1000,
      expiresAt: (now + this.credentialValiditySec) * 1000,
    };
  }

  // ─── Verification ─────────────────────────────────────────────────────

  /**
   * Verify a credential issued by this simulator.
   * Validates the JWT signature using the issuer's public key.
   */
  async verifyCredential(sdJwtString: string): Promise<{
    payload: SDJWTVCPayload;
    disclosures: Array<{ salt: string; name: string; value: unknown }>;
    isOver18?: boolean;
  }> {
    if (!this.publicKey) {
      throw new Error('Connector not initialized');
    }

    const parts = sdJwtString.split('~');
    const jwtPart = parts[0];
    const disclosureParts = parts.slice(1).filter(d => d.length > 0);

    // Verify JWT signature
    const { payload } = await jwtVerify(jwtPart, this.publicKey, {
      issuer: this.issuerDID,
    });

    // Parse disclosures
    const disclosures = disclosureParts.map(d => {
      const json = Buffer.from(d, 'base64url').toString('utf-8');
      const [salt, name, value] = JSON.parse(json);
      return { salt, name, value };
    });

    // Verify disclosure hashes match _sd array
    const sdArray = (payload as any)._sd as string[] | undefined;
    if (sdArray) {
      for (const dp of disclosureParts) {
        const hash = hashDisclosure(dp);
        if (!sdArray.includes(hash)) {
          throw new Error(`Disclosure hash mismatch: ${hash} not in _sd`);
        }
      }
    }

    return {
      payload: payload as unknown as SDJWTVCPayload,
      disclosures,
      isOver18: (payload as any).age_over_18,
    };
  }

  /**
   * Verify a credential using an external public key (JWK).
   * This is what a verifier would use — they don't have access to the connector instance.
   */
  static async verifyWithPublicKey(
    sdJwtString: string,
    publicKeyJwk: JWK,
    expectedIssuer: string
  ): Promise<{
    payload: SDJWTVCPayload;
    disclosures: Array<{ salt: string; name: string; value: unknown }>;
    isOver18?: boolean;
  }> {
    const parts = sdJwtString.split('~');
    const jwtPart = parts[0];
    const disclosureParts = parts.slice(1).filter(d => d.length > 0);

    const key = await importJWK(publicKeyJwk, 'ES256');
    const { payload } = await jwtVerify(jwtPart, key, {
      issuer: expectedIssuer,
    });

    const disclosures = disclosureParts.map(d => {
      const json = Buffer.from(d, 'base64url').toString('utf-8');
      const [salt, name, value] = JSON.parse(json);
      return { salt, name, value };
    });

    return {
      payload: payload as unknown as SDJWTVCPayload,
      disclosures,
      isOver18: (payload as any).age_over_18,
    };
  }

  // ─── Session Inspection ───────────────────────────────────────────────

  /**
   * Get a protocol session by ID (for debugging/testing).
   */
  getSession(sessionId: string): EIDProtocolSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Get all sessions.
   */
  getAllSessions(): EIDProtocolSession[] {
    return Array.from(this.sessions.values());
  }

  // ─── Attribute Verification ───────────────────────────────────────────

  /**
   * Verify an eID attribute.
   */
  async verifyAttribute(attribute: EIDAttribute): Promise<boolean> {
    if (this.mode === 'mock' || this.mode === 'simulator') {
      return true; // Simulated verification always succeeds
    }
    throw new Error('Attribute verification not yet implemented');
  }

  // ─── Private Helpers ──────────────────────────────────────────────────

  private async simulateDelay(): Promise<void> {
    if (this.simulatedDelayMs > 0) {
      await new Promise(r => setTimeout(r, this.simulatedDelayMs));
    }
  }

  /**
   * Legacy mock issuance (backward compatible, plain JWT).
   */
  private async legacyMockIssuance(
    request: EIDIssuanceRequest
  ): Promise<EIDIssuanceResponse> {
    if (!this.privateKey) {
      throw new Error('Mock issuer not initialized');
    }

    const now = Math.floor(Date.now() / 1000);
    const mockAttributes: Record<string, string> = {
      givenName: 'Max',
      familyName: 'Mustermann',
      dateOfBirth: '1990-01-01',
      nationality: 'DE',
      documentNumber: 'T22000001',
    };

    const claims: Record<string, any> = {
      iss: this.issuerDID,
      sub: request.userDID,
      iat: now,
      exp: now + 365 * 24 * 60 * 60,
      purpose: request.purpose,
    };

    for (const attr of request.requestedAttributes) {
      if (mockAttributes[attr]) {
        claims[attr] = mockAttributes[attr];
      }
    }

    const jwt = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .sign(this.privateKey);

    return {
      credential: jwt,
      format: 'jwt',
      issuer: this.issuerDID,
      issuedAt: now * 1000,
      expiresAt: (now + 365 * 24 * 60 * 60) * 1000,
    };
  }
}

// ─── Utility Functions ──────────────────────────────────────────────────────

/**
 * Compute age in years from a birthdate.
 */
export function computeAge(birthdate: Date, referenceDate: Date = new Date()): number {
  const age = referenceDate.getFullYear() - birthdate.getFullYear();
  const monthDiff = referenceDate.getMonth() - birthdate.getMonth();
  const dayDiff = referenceDate.getDate() - birthdate.getDate();
  if (monthDiff < 0 || (monthDiff === 0 && dayDiff < 0)) {
    return age - 1;
  }
  return age;
}

/**
 * Compute isOver18 predicate from a birthdate.
 */
export function isOver18(birthdate: Date): boolean {
  return computeAge(birthdate) >= 18;
}

export * from './types';
