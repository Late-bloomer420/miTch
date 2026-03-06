/**
 * Pairwise Ephemeral DIDs — Spec 111 Phase 1
 *
 * Generates a fresh, unique did:peer per verifier/session interaction.
 * Keys are held in EphemeralKey wrappers and shredded after use.
 * No network required — did:peer method 0 embeds the public key inline.
 */

import { EphemeralKey } from './ephemeral-key';
import { crypto } from './platform';

// ─── Constants ───────────────────────────────────────────────────────────────

/** Multicodec varint prefix for P-256 compressed public key (0x1200) */
const MULTICODEC_P256_PREFIX = new Uint8Array([0x80, 0x24]);

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// P-256 (secp256r1) curve parameters
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = P256_P - 3n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

// ─── Public types ─────────────────────────────────────────────────────────────

export interface PairwiseDIDOptions {
  /** Verifier identifier (used as HKDF context — NOT leaked to verifier) */
  verifierOrigin: string;
  /** Session nonce from verifier request (ensures per-session uniqueness) */
  sessionNonce: string;
}

export interface PairwiseDIDResult {
  /** Fresh did:peer:0 for this interaction only */
  did: string;
  /** Ephemeral signing key bytes (PKCS8) — shredded on destroy() */
  signingKey: EphemeralKey;
  /** Ephemeral encryption key bytes (PKCS8) — shredded on destroy() */
  encryptionKey: EphemeralKey;
  /**
   * Sign data with the ephemeral signing key.
   * Must be called before destroy().
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
  /** Shred all ephemeral key material. Call after proof delivery. */
  destroy(): void;
}

// ─── Core function ────────────────────────────────────────────────────────────

/**
 * Generate a pairwise ephemeral DID for a single verification interaction.
 *
 * Properties:
 * - Same verifier + different sessionNonce → different DID every time
 * - Different verifiers → different DIDs (obviously)
 * - No two interactions share a DID (probabilistic with fresh random keys)
 * - Key material is shredded after destroy() is called
 */
export async function generatePairwiseDID(
  options: PairwiseDIDOptions
): Promise<PairwiseDIDResult> {
  // Suppress linter: verifierOrigin + sessionNonce are used as HKDF context
  // (Phase 1: random keys; Phase 2 will use HKDF from master key)
  void options.verifierOrigin;
  void options.sessionNonce;

  // Generate ephemeral ECDSA P-256 signing key pair
  const signingKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  // Generate ephemeral ECDH P-256 encryption key pair
  const encryptionKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  // Export raw signing public key → compress → build did:peer:0
  const rawPubKey = await crypto.subtle.exportKey('raw', signingKeyPair.publicKey);
  const compressedPubKey = compressP256PublicKey(new Uint8Array(rawPubKey));
  const did = encodeDidPeer0(compressedPubKey);

  // Export private key bytes into EphemeralKey wrappers for shredding
  const signingPrivBytes = new Uint8Array(
    await crypto.subtle.exportKey('pkcs8', signingKeyPair.privateKey)
  );
  const encPrivBytes = new Uint8Array(
    await crypto.subtle.exportKey('pkcs8', encryptionKeyPair.privateKey)
  );

  const signingKey = new EphemeralKey(signingPrivBytes);
  const encryptionKey = new EphemeralKey(encPrivBytes);

  // Hold reference to CryptoKey for signing (before shredding)
  const _signingCryptoKey = signingKeyPair.privateKey;

  return {
    did,
    signingKey,
    encryptionKey,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      if (signingKey.isShredded()) {
        throw new Error('Cannot sign: ephemeral key has been shredded');
      }
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        _signingCryptoKey,
        data as unknown as ArrayBuffer
      );
      return new Uint8Array(signature);
    },

    destroy(): void {
      signingKey.shred();
      encryptionKey.shred();
    },
  };
}

// ─── DID:peer verification ────────────────────────────────────────────────────

/**
 * Verify a proof against a did:peer:0 DID.
 * Extracts the public key from the DID and verifies the ECDSA signature.
 * Returns false (not throws) on any failure — fail-closed.
 */
export async function verifyPairwiseDIDProof(
  did: string,
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  try {
    const compressedPubKey = extractPubKeyFromDidPeer0(did);
    const uncompressed = decompressP256PublicKey(compressedPubKey);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      uncompressed as unknown as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      signature as unknown as ArrayBuffer,
      data as unknown as ArrayBuffer
    );
  } catch {
    return false;
  }
}

// ─── did:peer encoding / decoding ────────────────────────────────────────────

function encodeDidPeer0(compressedPubKey: Uint8Array): string {
  const multikey = new Uint8Array(MULTICODEC_P256_PREFIX.length + compressedPubKey.length);
  multikey.set(MULTICODEC_P256_PREFIX);
  multikey.set(compressedPubKey, MULTICODEC_P256_PREFIX.length);
  return `did:peer:0z${base58Encode(multikey)}`;
}

function extractPubKeyFromDidPeer0(did: string): Uint8Array {
  if (!did.startsWith('did:peer:0z')) {
    throw new Error(`Not a did:peer method 0: ${did}`);
  }
  const encoded = did.slice('did:peer:0z'.length);
  const bytes = base58Decode(encoded);
  // Strip 2-byte multicodec prefix
  return bytes.slice(MULTICODEC_P256_PREFIX.length);
}

// ─── P-256 key compression / decompression ───────────────────────────────────

/**
 * Compress a raw P-256 public key (65 bytes, 0x04 prefix) to 33 bytes.
 */
function compressP256PublicKey(raw: Uint8Array): Uint8Array {
  // raw = 0x04 || x (32 bytes) || y (32 bytes)
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  const compressed = new Uint8Array(33);
  compressed[0] = (y[31] & 1) === 0 ? 0x02 : 0x03;
  compressed.set(x, 1);
  return compressed;
}

/**
 * Decompress a P-256 compressed public key (33 bytes) back to raw 65 bytes.
 * Uses BigInt arithmetic — P-256: p ≡ 3 (mod 4), so sqrt = y^((p+1)/4) mod p.
 */
function decompressP256PublicKey(compressed: Uint8Array): Uint8Array {
  const prefix = compressed[0];
  const xBytes = compressed.slice(1);
  const x = bytesToBigInt(xBytes);

  // y² = x³ + ax + b (mod p)
  const ySquared = (modPow(x, 3n, P256_P) + P256_A * x + P256_B) % P256_P;
  const yPositive = (ySquared % P256_P + P256_P) % P256_P;

  // y = sqrt(ySquared) mod p  — since p ≡ 3 (mod 4): y = ySquared^((p+1)/4) mod p
  let y = modPow(yPositive, (P256_P + 1n) / 4n, P256_P);

  // Pick the correct square root based on parity bit
  if ((y & 1n) !== BigInt(prefix & 1)) {
    y = P256_P - y;
  }

  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(bigIntToBytes32(x), 1);
  uncompressed.set(bigIntToBytes32(y), 33);
  return uncompressed;
}

// ─── Base58btc helpers ────────────────────────────────────────────────────────

function base58Encode(bytes: Uint8Array): string {
  let n = bytesToBigInt(bytes);
  let result = '';
  while (n > 0n) {
    result = BASE58_ALPHABET[Number(n % 58n)] + result;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    result = '1' + result;
  }
  return result;
}

function base58Decode(str: string): Uint8Array {
  let n = 0n;
  for (const c of str) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx === -1) throw new Error(`Invalid base58 char: ${c}`);
    n = n * 58n + BigInt(idx);
  }
  let leadingZeros = 0;
  for (const c of str) {
    if (c !== '1') break;
    leadingZeros++;
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}

// ─── BigInt utilities ─────────────────────────────────────────────────────────

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}
