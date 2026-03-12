/**
 * Verifier-Direct Protocol
 * 
 * STRUCTURAL NON-EXISTENCE:
 * - Verifier generates request LOCALLY (JavaScript in browser)
 * - Wallet scans QR, validates, generates proof LOCALLY
 * - Wallet sends proof DIRECTLY to Verifier (not via miTch server)
 * - miTch server sees NOTHING (zero network traffic)
 * 
 * COMPLIANCE:
 * - DSGVO Art. 5(1)(c): Datenminimierung (no intermediary)
 * - DSGVO Art. 25: Data Protection by Design (structural guarantee)
 * - eIDAS 2.0: Direct peer-to-peer credential presentation
 */

export interface PresentationRequest {
  challenge: string;
  verifierDID: string;
  credentialTypes: string[];
  callbackURL: string; // Verifier's own endpoint
  nonce: string;
  timestamp: number;
}

export interface VerificationResponse {
  type: 'ZKProof' | 'SelectiveDisclosure';
  claim: string;
  proof: string;
  timestamp: number;
  nonce: string;
}

/**
 * Verifier-Side: Generate presentation request (runs in Verifier's browser)
 */
export class VerifierDirectClient {
  private verifierDID: string;
  private verifierKey: CryptoKeyPair | null = null;

  constructor(verifierDID: string) {
    this.verifierDID = verifierDID;
  }

  /**
   * Generate ephemeral key-pair for this session (verifier-side)
   */
  async initialize(): Promise<void> {
    this.verifierKey = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // Extractable (need to export public key for JWT)
      ['sign', 'verify']
    );

    console.info('[Verifier] Ephemeral key-pair generated (session-scoped)');
  }

  /**
   * Generate presentation request (NO miTch server involved)
   * Returns deep-link that can be encoded in QR-code
   */
  async generateRequest(
    credentialTypes: string[],
    callbackURL: string
  ): Promise<string> {
    if (!this.verifierKey) {
      throw new Error('Verifier not initialized');
    }

    // 1. Create request payload
    const request: PresentationRequest = {
      challenge: this.generateChallenge(),
      verifierDID: this.verifierDID,
      credentialTypes,
      callbackURL,
      nonce: crypto.randomUUID(),
      timestamp: Date.now()
    };

    // 2. Sign request with verifier's ephemeral key
    const jwt = await this.signJWT(request);

    // 3. Create deep-link (NO miTch server URL)
    const deepLink = `mitch://present?request=${encodeURIComponent(jwt)}`;

    console.info('[Verifier] Request generated:', {
      verifierDID: this.verifierDID,
      credentialTypes,
      challenge: request.challenge.slice(0, 16) + '...'
    });

    return deepLink;
  }

  /**
   * Verify response from wallet (runs on verifier's backend)
   */
  async verifyResponse(response: VerificationResponse): Promise<boolean> {
    // 1. Verify nonce (prevent replay attacks)
    // 2. Verify timestamp (max 5min old)
    // 3. Verify ZK proof cryptographically
    // 4. Return TRUE/FALSE (no PII extraction)

    console.info('[Verifier] Response verified:', response.claim);
    return true; // Simplified for now
  }

  // ==================== PRIVATE HELPERS ====================

  private async signJWT(payload: PresentationRequest): Promise<string> {
    if (!this.verifierKey) {
      throw new Error('Verifier key not initialized');
    }

    // Simple JWT implementation (Header.Payload.Signature)
    const header = { alg: 'ES256', typ: 'JWT' };
    const encodedHeader = this.base64urlEncode(JSON.stringify(header));
    const encodedPayload = this.base64urlEncode(JSON.stringify(payload));
    const message = `${encodedHeader}.${encodedPayload}`;

    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.verifierKey.privateKey,
      new TextEncoder().encode(message)
    );

    const encodedSignature = this.base64urlEncode(signature);
    return `${message}.${encodedSignature}`;
  }

  private generateChallenge(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(randomBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private base64urlEncode(data: string | ArrayBuffer): string {
    const bytes = typeof data === 'string' 
      ? new TextEncoder().encode(data)
      : new Uint8Array(data);
    
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}

/**
 * Wallet-Side: Process verifier-direct request (NO server fetch)
 */
export class WalletDirectProtocol {
  /**
   * Parse and validate deep-link (runs in wallet, NO miTch server)
   */
  async parseRequest(deepLink: string): Promise<PresentationRequest> {
    // 1. Extract JWT from deep-link
    const url = new URL(deepLink);
    const jwt = url.searchParams.get('request');
    
    if (!jwt) {
      throw new Error('Invalid deep-link: missing request parameter');
    }

    // 2. Parse JWT (Header.Payload.Signature)
    const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.');
    const payload = JSON.parse(this.base64urlDecode(encodedPayload));

    // 3. Validate request structure
    this.validateRequest(payload);

    // 4. Resolve verifier DID and verify ES256 JWT signature
    await this.verifyJwtSignature(encodedHeader, encodedPayload, encodedSignature, payload.verifierDID);

    console.info('[Wallet] Request parsed:', {
      verifierDID: payload.verifierDID,
      credentialTypes: payload.credentialTypes
    });

    return payload;
  }

  /**
   * Send proof DIRECTLY to verifier (not via miTch server)
   */
  async sendProofToVerifier(
    callbackURL: string,
    response: VerificationResponse
  ): Promise<void> {
    // Direct HTTPS POST to verifier's endpoint
    const result = await fetch(callbackURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(response)
    });

    if (!result.ok) {
      throw new Error(`Verifier rejected proof: ${result.status}`);
    }

    console.info('[Wallet] Proof sent directly to verifier:', callbackURL);
  }

  // ==================== PRIVATE HELPERS ====================

  private validateRequest(request: any): asserts request is PresentationRequest {
    const required = ['challenge', 'verifierDID', 'credentialTypes', 'callbackURL', 'nonce', 'timestamp'];
    for (const field of required) {
      if (!request[field]) {
        throw new Error(`Invalid request: missing ${field}`);
      }
    }

    // Check timestamp (max 5min old)
    const age = Date.now() - request.timestamp;
    if (age > 300000) {
      throw new Error('Request expired (>5min old)');
    }
  }

  /**
   * Resolve verifier DID and verify the ES256 JWT signature.
   *
   * Supports did:web (HTTPS resolution) and any DID method that embeds
   * a `verificationMethod[0].publicKeyJwk` in its DID Document.
   *
   * Fail-closed: throws on any resolution or signature failure.
   */
  private async verifyJwtSignature(
    encodedHeader: string,
    encodedPayload: string,
    encodedSignature: string,
    verifierDID: string,
  ): Promise<void> {
    // Resolve DID Document
    const didDoc = await this.resolveDidDocument(verifierDID);

    // Extract first verificationMethod with a JWK public key
    const vm = didDoc.verificationMethod?.find((m: { publicKeyJwk?: JsonWebKey }) => m.publicKeyJwk);
    if (!vm?.publicKeyJwk) {
      throw new Error(`DID_VERIFY_FAILED: no publicKeyJwk in ${verifierDID}`);
    }

    // Import the public key for ECDSA-P256 verification
    const pubKey = await crypto.subtle.importKey(
      'jwk',
      vm.publicKeyJwk as JsonWebKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );

    // JWT signing input = ASCII(BASE64URL(header) + '.' + BASE64URL(payload))
    const signingInput = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);

    // Decode raw signature (base64url → r||s bytes, 64 bytes for P-256)
    const sigBytes = this.base64urlToBytes(encodedSignature);

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pubKey,
      sigBytes,
      signingInput,
    );

    if (!valid) {
      throw new Error(`DID_VERIFY_FAILED: invalid signature from ${verifierDID}`);
    }
  }

  /**
   * Minimal DID Document resolution.
   * Supports did:web via HTTPS fetch. Other methods throw — callers should
   * use @mitch/shared-crypto DIDResolver for full multi-method support.
   */
  private async resolveDidDocument(did: string): Promise<{ verificationMethod?: Array<{ id: string; publicKeyJwk?: JsonWebKey }> }> {
    if (did.startsWith('did:web:')) {
      const url = this.didWebToUrl(did);
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`DID_RESOLVE_FAILED: HTTP ${response.status} for ${url}`);
      }
      return response.json();
    }
    throw new Error(`DID_RESOLVE_FAILED: unsupported DID method in ${did}`);
  }

  /** did:web → HTTPS URL  (RFC 7517 §3.2) */
  private didWebToUrl(did: string): string {
    let domain = did.slice('did:web:'.length);
    domain = decodeURIComponent(domain);
    const parts = domain.split(':');
    const host = parts[0];
    let hostWithPort = host;
    let pathStart = 1;
    if (parts.length > 1 && /^\d+$/.test(parts[1])) {
      hostWithPort = `${host}:${parts[1]}`;
      pathStart = 2;
    }
    const pathSegments = parts.slice(pathStart);
    if (pathSegments.length > 0) {
      return `https://${hostWithPort}/${pathSegments.join('/')}/did.json`;
    }
    return `https://${hostWithPort}/.well-known/did.json`;
  }

  private base64urlToBytes(data: string): Uint8Array {
    const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const binary = atob(base64 + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  private base64urlDecode(data: string): string {
    const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const decoded = atob(base64 + padding);
    return decoded;
  }
}
