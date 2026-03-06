/**
 * Pairwise Ephemeral DIDs — Spec 111 Phase 1 + Phase 2
 *
 * Generates a fresh, unique did:peer per verifier/session interaction.
 * Keys are held in EphemeralKey wrappers and shredded after use.
 * No network required — did:peer method 0 embeds the public key inline.
 *
 * Phase 1: Random ephemeral keys (fully unlinkable, non-recoverable)
 * Phase 2: HKDF-derived keys from wallet master key (recoverable, deterministic)
 */

import { EphemeralKey } from './ephemeral-key';
import { crypto } from './platform';
import type { DIDDocument } from '@mitch/shared-types';

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

// ─── U-01: HKDF-Based Deterministic Pairwise DID ─────────────────────────────

/**
 * Spec 111 Phase 2 — Generate pairwise DID from wallet master key material.
 *
 * Unlike Phase 1 (fully random), this uses HKDF to derive a deterministic
 * signing key from a master secret. This enables key recovery and consistent
 * DID generation per verifier+session combination.
 *
 * Unlinkability properties:
 * - Different verifierOrigin → different derived key → different DID
 * - Different sessionNonce → different derived key → different DID
 * - Cannot correlate two DIDs without the master key (information-theoretic)
 *
 * @param masterKeyMaterial Raw bytes of the wallet master key (32+ bytes recommended)
 * @param verifierOrigin Verifier identifier (used as HKDF info — NOT sent to verifier)
 * @param sessionNonce Session-specific nonce (prevents cross-session correlation)
 */
export async function generatePairwiseDIDFromMasterKey(
  masterKeyMaterial: Uint8Array,
  verifierOrigin: string,
  sessionNonce: string
): Promise<PairwiseDIDResult> {
  // Step 1: Import master key material as HKDF base key
  const baseKey = await crypto.subtle.importKey(
    'raw',
    masterKeyMaterial.slice(0) as unknown as Uint8Array<ArrayBuffer>,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  // Step 2: Encode HKDF info = verifierOrigin || 0x00 || sessionNonce
  const encoder = new TextEncoder();
  const infoStr = `${verifierOrigin}\x00${sessionNonce}\x00signing`;
  const infoBytes = encoder.encode(infoStr);
  const saltBytes = encoder.encode('mitch-pairwise-did-v1');

  // Step 3: Derive 32 bytes for signing key via HKDF-SHA-256
  const derivedSigningBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: infoBytes,
    },
    baseKey,
    256
  );

  // Step 4: Derive separate 32 bytes for encryption key
  const infoEncStr = `${verifierOrigin}\x00${sessionNonce}\x00encryption`;
  const infoEncBytes = encoder.encode(infoEncStr);
  const derivedEncBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: infoEncBytes,
    },
    baseKey,
    256
  );

  const signingPrivBytes = new Uint8Array(derivedSigningBits);
  const encPrivBytes = new Uint8Array(derivedEncBits);

  // Step 5: Build P-256 PKCS8-encoded private key from raw bytes
  const signingPKCS8 = buildP256PKCS8(signingPrivBytes);
  const _encPKCS8 = buildP256PKCS8(encPrivBytes);

  // Step 6: Import as ECDSA signing key pair
  const signingCryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    signingPKCS8.slice(0) as unknown as Uint8Array<ArrayBuffer>,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );

  // Step 7: Derive public key and build did:peer:0
  const rawPubKey = await crypto.subtle.exportKey('raw', await getPublicKeyFromPrivate(signingCryptoKey));
  const compressedPubKey = compressP256PublicKey(new Uint8Array(rawPubKey));
  const did = encodeDidPeer0(compressedPubKey);

  // Step 8: Wrap in EphemeralKey for shredding
  const signingKey = new EphemeralKey(signingPrivBytes);
  const encryptionKey = new EphemeralKey(encPrivBytes);

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
        signingCryptoKey,
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

/**
 * Get the public key from a private ECDSA CryptoKey.
 * Exports the private key to PKCS8, then re-imports as key pair
 * by exporting raw public key from the JWK representation.
 */
async function getPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  // Remove the private key component — keep only public parts
  const { d: _d, key_ops: _ko, ...publicJwk } = jwk;
  return await crypto.subtle.importKey(
    'jwk',
    { ...publicJwk, key_ops: ['verify'] },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

/**
 * Build a PKCS8 DER-encoded unencrypted P-256 private key from 32 raw bytes.
 *
 * Structure (RFC 5958 / SEC 1):
 *   SEQUENCE {
 *     INTEGER 0           -- version
 *     SEQUENCE {          -- algorithmIdentifier
 *       OID ecPublicKey
 *       OID prime256v1
 *     }
 *     OCTET STRING {      -- privateKey
 *       SEQUENCE {        -- ECPrivateKey (SEC 1)
 *         INTEGER 1       -- version
 *         OCTET STRING d  -- 32 private key bytes
 *       }
 *     }
 *   }
 */
function buildP256PKCS8(d: Uint8Array): Uint8Array {
  // ECPrivateKey SEQUENCE { version INTEGER 1, privateKey OCTET STRING d }
  const ecPrivKey = new Uint8Array([
    0x30, 0x25,       // SEQUENCE, 37 bytes
    0x02, 0x01, 0x01, // INTEGER 1 (EC private key version)
    0x04, 0x20,       // OCTET STRING, 32 bytes
    ...d,
  ]);

  // AlgorithmIdentifier SEQUENCE { OID ecPublicKey, OID prime256v1 }
  const algId = new Uint8Array([
    0x30, 0x13,                               // SEQUENCE, 19 bytes
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1 OID
  ]);

  // PrivateKeyInfo version
  const version = new Uint8Array([0x02, 0x01, 0x00]);

  // Wrap ECPrivateKey in OCTET STRING
  const privateKeyOctet = new Uint8Array(2 + ecPrivKey.length);
  privateKeyOctet[0] = 0x04;
  privateKeyOctet[1] = ecPrivKey.length;
  privateKeyOctet.set(ecPrivKey, 2);

  const innerLen = version.length + algId.length + privateKeyOctet.length;
  const outer = new Uint8Array(2 + innerLen);
  outer[0] = 0x30;
  outer[1] = innerLen;
  let offset = 2;
  outer.set(version, offset); offset += version.length;
  outer.set(algId, offset); offset += algId.length;
  outer.set(privateKeyOctet, offset);

  return outer;
}

// ─── U-02: did:peer:0 Inline DID Document Resolution ──────────────────────────

/**
 * Spec 111 — Resolve a did:peer:0 DID to a DID Document inline.
 * No network required — the public key is embedded in the DID itself.
 *
 * Returns a minimal DID Document with the embedded P-256 public key
 * as a JsonWebKey2020 verification method.
 */
export async function resolveDidPeer0(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:peer:0z')) {
    throw new Error(`resolveDidPeer0: not a did:peer method 0: ${did}`);
  }

  const compressedPubKey = extractPubKeyFromDidPeer0(did);
  const uncompressed = decompressP256PublicKey(compressedPubKey);

  // Import as ECDSA public key to export as JWK
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    uncompressed as unknown as ArrayBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);

  const vmId = `${did}#key-1`;
  const doc: DIDDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: jwk.kty!,
          crv: jwk.crv!,
          x: jwk.x!,
          y: jwk.y!,
        },
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };

  return doc;
}
