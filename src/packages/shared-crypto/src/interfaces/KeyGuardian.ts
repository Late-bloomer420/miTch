import { KeyProtectionLevel } from "../types/KeyProtectionLevel";

/** Result of creating a signing key (ECDSA-P256). */
export type KeyCreationResult =
  | {
      level: KeyProtectionLevel.SOFTWARE_EPHEMERAL | KeyProtectionLevel.SOFTWARE_PERSISTED;
      publicKeyJwk: JsonWebKey;
      keyId: string;
    }
  | {
      level: KeyProtectionLevel.HARDWARE_BOUND;
      publicKeyJwk: JsonWebKey;
      keyId: string;
      credentialId: string;
    };

/** Result of creating an encryption key (ECDH-P256). Separate from signing keys (G-07). */
export interface EncryptionKeyCreationResult {
  /** Public ECDH key in JWK format — share with senders so they can derive a shared secret. */
  publicKeyJwk: JsonWebKey;
  /** Opaque key ID for later use in deriveSharedSecret / unwrapKey. */
  encKeyId: string;
}

/**
 * KeyGuardian — manages cryptographic key material.
 *
 * G-07: Signing keys (ECDSA) and encryption keys (ECDH) are strictly separated.
 * A signing key MUST NOT be used for encryption and vice versa.
 */
export interface KeyGuardian {
  getLevel(): Promise<KeyProtectionLevel>;
  /** Create a signing key pair (ECDSA-P256). */
  createKey(opts: { userId: string }): Promise<KeyCreationResult>;
  /** Sign a challenge with the named signing key. */
  sign(opts: { keyId: string; challenge: Uint8Array }): Promise<Uint8Array>;
  /** Create an encryption key pair (ECDH-P256) — separate from signing keys (G-07). */
  createEncryptionKey(opts: { userId: string }): Promise<EncryptionKeyCreationResult>;
  /** Derive a shared AES-GCM key from our ECDH private key and a sender's public key. */
  deriveSharedSecret(opts: { encKeyId: string; senderPublicKeyJwk: JsonWebKey }): Promise<CryptoKey>;
}
