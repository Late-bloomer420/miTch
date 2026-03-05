import { KeyProtectionLevel } from './types/KeyProtectionLevel';
import type { KeyGuardian, KeyCreationResult, EncryptionKeyCreationResult } from './interfaces/KeyGuardian';

export class SoftwareKeyGuardian implements KeyGuardian {
  // Signing keys (ECDSA-P256) — G-07: separate from encryption keys
  private signingKeys = new Map<string, CryptoKeyPair>();
  // Encryption keys (ECDH-P256) — G-07: separate from signing keys
  private encryptionKeys = new Map<string, CryptoKeyPair>();

  async getLevel(): Promise<KeyProtectionLevel> {
    return KeyProtectionLevel.SOFTWARE_EPHEMERAL;
  }

  /** Create a signing key pair (ECDSA-P256). MUST NOT be used for encryption (G-07). */
  async createKey(opts: { userId: string }): Promise<KeyCreationResult> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // private key non-extractable
      ['sign', 'verify']
    );

    const keyId = `kg-sign-${opts.userId}-${Date.now()}`;
    this.signingKeys.set(keyId, keyPair);

    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    return {
      level: KeyProtectionLevel.SOFTWARE_EPHEMERAL,
      publicKeyJwk,
      keyId,
    };
  }

  async sign(opts: { keyId: string; challenge: Uint8Array }): Promise<Uint8Array> {
    const keyPair = this.signingKeys.get(opts.keyId);
    if (!keyPair) {
      throw new Error(`Signing key not found: ${opts.keyId}`);
    }

    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      opts.challenge as BufferSource
    );
    return new Uint8Array(sig);
  }

  /**
   * Create an encryption key pair (ECDH-P256). MUST NOT be used for signing (G-07).
   * The public key is returned for distribution to senders.
   * The private key stays in memory and is referenced by encKeyId.
   */
  async createEncryptionKey(opts: { userId: string }): Promise<EncryptionKeyCreationResult> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false, // private key non-extractable
      ['deriveKey', 'deriveBits']
    );

    const encKeyId = `kg-enc-${opts.userId}-${Date.now()}`;
    this.encryptionKeys.set(encKeyId, keyPair);

    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    return { publicKeyJwk, encKeyId };
  }

  /**
   * Derive a shared AES-256-GCM key using ECDH between our private key and the sender's public key.
   * Use the result to decrypt incoming encrypted payloads.
   */
  async deriveSharedSecret(opts: { encKeyId: string; senderPublicKeyJwk: JsonWebKey }): Promise<CryptoKey> {
    const keyPair = this.encryptionKeys.get(opts.encKeyId);
    if (!keyPair) {
      throw new Error(`Encryption key not found: ${opts.encKeyId}`);
    }

    const senderPublicKey = await crypto.subtle.importKey(
      'jwk',
      opts.senderPublicKeyJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: senderPublicKey },
      keyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }
}

export default SoftwareKeyGuardian;
