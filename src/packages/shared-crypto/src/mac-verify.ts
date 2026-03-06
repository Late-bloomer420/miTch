/**
 * MAC-based Verification (ECDH + HMAC-SHA2) — C-02
 * https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-geordnet/tr03116/TR-03116_node.html
 *
 * Implements:
 * - ECDH Key Agreement (secp256r1 / P-256) via WebCrypto
 * - HMAC-SHA-256 MAC computation over SD-JWT disclosures
 * - MAC-based verification path as alternative to ECDSA signatures
 * - Use case: Issuer and Verifier know each other (closed ecosystem, BSI TR-03116)
 *
 * Security Note:
 * Unlike ECDSA signatures, MAC-based verification requires the verifier to hold
 * the shared secret (symmetric). Use only in closed/pre-registered ecosystems.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ECDHKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export interface MACResult {
    /** HMAC-SHA-256 over the input, hex-encoded */
    mac: string;
    /** Algorithm identifier */
    alg: 'HMAC-SHA-256';
}

export interface MACVerificationResult {
    ok: boolean;
    error?: string;
}

// ─── ECDH Key Agreement ───────────────────────────────────────────────────────

/**
 * Generate a P-256 (secp256r1) ECDH key pair.
 * Used for key agreement in closed-ecosystem MAC flows.
 */
export async function generateECDHKeyPair(): Promise<ECDHKeyPair> {
    const pair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );
    return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

/**
 * Perform ECDH key agreement and derive a shared secret key (HMAC-SHA-256).
 * Both parties must use the other's public key to derive the same secret.
 *
 * @param ownPrivateKey  Own ECDH private key
 * @param peerPublicKey  Peer's ECDH public key
 * @returns Derived HMAC-SHA-256 key (256 bits)
 */
export async function deriveSharedHMACKey(
    ownPrivateKey: CryptoKey,
    peerPublicKey: CryptoKey
): Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
        {
            name: 'ECDH',
            public: peerPublicKey,
        },
        ownPrivateKey,
        {
            name: 'HMAC',
            hash: 'SHA-256',
            length: 256,
        },
        false, // not extractable — stays in WebCrypto
        ['sign', 'verify']
    );
}

// ─── MAC Computation ──────────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA-256 MAC over a message.
 * Used to authenticate SD-JWT disclosures in closed-ecosystem flows.
 *
 * @param message  Data to MAC (e.g. concatenation of SD-JWT disclosures)
 * @param hmacKey  Derived HMAC key (from ECDH agreement)
 */
export async function computeMAC(message: string | Uint8Array, hmacKey: CryptoKey): Promise<MACResult> {
    const data = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;

    const macBuffer = await crypto.subtle.sign('HMAC', hmacKey, data as Uint8Array<ArrayBuffer>);
    const macHex = Array.from(new Uint8Array(macBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return { mac: macHex, alg: 'HMAC-SHA-256' };
}

/**
 * Verify HMAC-SHA-256 MAC over a message.
 * Constant-time comparison via WebCrypto.
 *
 * @param message  Original data
 * @param mac  Hex-encoded MAC to verify
 * @param hmacKey  Derived HMAC key
 */
export async function verifyMAC(
    message: string | Uint8Array,
    mac: string,
    hmacKey: CryptoKey
): Promise<MACVerificationResult> {
    const data = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;

    // Convert hex MAC back to bytes
    const macBytes = new Uint8Array(
        (mac.match(/.{1,2}/g) ?? []).map(byte => parseInt(byte, 16))
    );

    try {
        const isValid = await crypto.subtle.verify('HMAC', hmacKey, macBytes as Uint8Array<ArrayBuffer>, data as Uint8Array<ArrayBuffer>);
        return isValid
            ? { ok: true }
            : { ok: false, error: 'MAC verification failed: digest mismatch' };
    } catch (e: unknown) {
        return {
            ok: false,
            error: `MAC verification error: ${e instanceof Error ? e.message : String(e)}`,
        };
    }
}

// ─── SD-JWT Disclosure MAC ────────────────────────────────────────────────────

/**
 * Compute MAC over a set of SD-JWT disclosures.
 * Disclosures are sorted + concatenated with '~' separator for determinism.
 * Used in closed-ecosystem scenarios (e.g. BSI TR-03116 Annex B).
 */
export async function macSDJWTDisclosures(
    disclosures: string[],
    hmacKey: CryptoKey
): Promise<MACResult> {
    // Sort for determinism — same set → same MAC regardless of order
    const sorted = [...disclosures].sort();
    const concatenated = sorted.join('~');
    return computeMAC(concatenated, hmacKey);
}

/**
 * Verify MAC over SD-JWT disclosures.
 */
export async function verifySDJWTDisclosureMAC(
    disclosures: string[],
    mac: string,
    hmacKey: CryptoKey
): Promise<MACVerificationResult> {
    const sorted = [...disclosures].sort();
    const concatenated = sorted.join('~');
    return verifyMAC(concatenated, mac, hmacKey);
}
