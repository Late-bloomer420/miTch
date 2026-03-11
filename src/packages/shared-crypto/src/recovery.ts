
/**
 * RecoveryService: Implements "Trust Circle" Social Recovery.
 *
 * F-01 fix: replaced XOR 3-of-3 scheme with real Shamir's Secret Sharing (2-of-3)
 * over GF(2^8) (AES field, irreducible polynomial 0x11B).
 *
 * Scheme: degree-1 polynomial over GF(2^8), 3 shares at x=1,2,3.
 * Any 2 shares are sufficient for recovery (Lagrange interpolation at x=0).
 * Share format (per byte of secret): [x-coord (1 byte) || y-values (secret.length bytes)].
 */

// ─── GF(2^8) arithmetic (AES field, poly = x^8 + x^4 + x^3 + x + 1 = 0x11B) ──

function gf256Mul(a: number, b: number): number {
    let result = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xFF;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

function gf256Inv(a: number): number {
    // Fermat's little theorem: a^(2^8 - 2) = a^254 = a^{-1} in GF(2^8)
    let result = 1;
    let base = a;
    let exp = 254;
    while (exp > 0) {
        if (exp & 1) result = gf256Mul(result, base);
        base = gf256Mul(base, base);
        exp >>= 1;
    }
    return result;
}

function gf256Div(a: number, b: number): number {
    return gf256Mul(a, gf256Inv(b));
}

// ─── Shamir split / reconstruct ───────────────────────────────────────────────

/**
 * Split `secret` into 3 shares using a degree-1 polynomial over GF(2^8).
 * Any 2 shares reconstruct the secret.
 *
 * Share format: first byte = x-coordinate (1, 2, or 3), rest = y-values.
 */
function shamirSplit(secret: Uint8Array): [Uint8Array, Uint8Array, Uint8Array] {
    const n = secret.length;
    const s1 = new Uint8Array(n + 1);
    const s2 = new Uint8Array(n + 1);
    const s3 = new Uint8Array(n + 1);
    s1[0] = 1; s2[0] = 2; s3[0] = 3;

    const randomCoeffs = new Uint8Array(n);
    crypto.getRandomValues(randomCoeffs);

    for (let i = 0; i < n; i++) {
        // Polynomial f(x) = secret[i] + randomCoeffs[i] * x  (over GF(2^8))
        // f(0) = secret[i]  (the value we want to recover)
        const a0 = secret[i];
        const a1 = randomCoeffs[i];
        s1[i + 1] = a0 ^ gf256Mul(a1, 1);
        s2[i + 1] = a0 ^ gf256Mul(a1, 2);
        s3[i + 1] = a0 ^ gf256Mul(a1, 3);
    }
    return [s1, s2, s3];
}

/**
 * Recover the secret from any 2 shares using Lagrange interpolation at x=0.
 */
function shamirReconstruct(shares: Uint8Array[]): Uint8Array {
    if (shares.length < 2) {
        throw new Error('RECOVERY_FAILED: Need at least 2 shares');
    }
    const n = shares[0].length - 1;
    const result = new Uint8Array(n);
    const used = shares.slice(0, 2); // degree-1 polynomial: 2 points suffice

    for (let i = 0; i < n; i++) {
        let secret = 0;
        for (let j = 0; j < used.length; j++) {
            const xj = used[j][0];
            const yj = used[j][i + 1];
            // Lagrange basis polynomial at x=0
            let num = 1, den = 1;
            for (let k = 0; k < used.length; k++) {
                if (k === j) continue;
                const xk = used[k][0];
                num = gf256Mul(num, xk);          // 0 ^ xk = xk
                den = gf256Mul(den, xj ^ xk);
            }
            secret ^= gf256Mul(yj, gf256Div(num, den));
        }
        result[i] = secret;
    }
    return result;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export class RecoveryService {
    /**
     * Splits a Master Key (as hex string) into 3 shares using Shamir's Secret Sharing (2-of-3).
     * Any 2 of the 3 shares are sufficient to recover the key.
     */
    static async splitMasterKey(masterKeyHex: string): Promise<string[]> {
        const keyBytes = new TextEncoder().encode(masterKeyHex);
        const [s1, s2, s3] = shamirSplit(keyBytes);
        return [this.toBase64(s1), this.toBase64(s2), this.toBase64(s3)];
    }

    /**
     * Recovers the Master Key from any 2 (or more) shares.
     */
    static async recover(fragments: string[]): Promise<string> {
        if (fragments.length < 2) {
            throw new Error('RECOVERY_FAILED: At least 2 of 3 shares are required.');
        }
        const shares = fragments.map(f => this.fromBase64(f));
        const recovered = shamirReconstruct(shares);
        return new TextDecoder().decode(recovered);
    }

    private static toBase64(bytes: Uint8Array): string {
        return btoa(String.fromCharCode(...Array.from(bytes)));
    }

    private static fromBase64(b64: string): Uint8Array {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}
