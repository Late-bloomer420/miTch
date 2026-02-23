/**
 * Crypto-Shredding — Provable data destruction
 * 
 * Data is encrypted with ephemeral keys.
 * Destroying the key = destroying the data (mathematically).
 * Each shred event produces a proof for the audit chain.
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { ShredProof } from "./auditChain";

// ─── Types ───────────────────────────────────────────────────────

export interface EphemeralKey {
  keyId: string;
  key: Buffer;         // 32 bytes for AES-256
  iv: Buffer;          // 16 bytes
  algorithm: string;
  createdAt: string;
  destroyed: boolean;
}

export interface EncryptedData {
  keyId: string;
  ciphertext: string;  // hex-encoded
  algorithm: string;
}

// ─── Ephemeral Key Manager ───────────────────────────────────────

export class EphemeralKeyManager {
  private keys: Map<string, EphemeralKey> = new Map();

  /**
   * Create a new ephemeral key for a transaction.
   */
  createKey(): EphemeralKey {
    const keyId = `k_trans_${randomBytes(8).toString("hex")}`;
    const ephemeral: EphemeralKey = {
      keyId,
      key: randomBytes(32),
      iv: randomBytes(16),
      algorithm: "aes-256-cbc",
      createdAt: new Date().toISOString(),
      destroyed: false,
    };
    this.keys.set(keyId, ephemeral);
    return ephemeral;
  }

  /**
   * Encrypt data with an ephemeral key.
   */
  encrypt(keyId: string, plaintext: string): EncryptedData {
    const ek = this.keys.get(keyId);
    if (!ek) throw new Error("key_not_found");
    if (ek.destroyed) throw new Error("key_destroyed");

    const cipher = createCipheriv(ek.algorithm, ek.key, ek.iv);
    let encrypted = cipher.update(plaintext, "utf8", "hex");
    encrypted += cipher.final("hex");

    return {
      keyId,
      ciphertext: encrypted,
      algorithm: ek.algorithm,
    };
  }

  /**
   * Decrypt data (only possible if key hasn't been shredded).
   */
  decrypt(encrypted: EncryptedData): string {
    const ek = this.keys.get(encrypted.keyId);
    if (!ek) throw new Error("key_not_found");
    if (ek.destroyed) throw new Error("key_destroyed_data_irrecoverable");

    const decipher = createDecipheriv(ek.algorithm, ek.key, ek.iv);
    let decrypted = decipher.update(encrypted.ciphertext, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }

  /**
   * DESTROY a key — crypto-shred.
   * After this, all data encrypted with this key is irrecoverable.
   * Returns a proof for the audit chain.
   */
  shred(keyId: string): ShredProof {
    const ek = this.keys.get(keyId);
    if (!ek) throw new Error("key_not_found");
    if (ek.destroyed) throw new Error("already_destroyed");

    // Zero out the key material
    ek.key.fill(0);
    ek.iv.fill(0);
    ek.destroyed = true;

    const proof: ShredProof = {
      keyId,
      algorithm: ek.algorithm,
      destroyedAt: new Date().toISOString(),
      method: "key_zeroed",
    };

    return proof;
  }

  /**
   * Check if a key exists and is active.
   */
  isActive(keyId: string): boolean {
    const ek = this.keys.get(keyId);
    return ek !== undefined && !ek.destroyed;
  }

  /**
   * Check if a key has been destroyed.
   */
  isDestroyed(keyId: string): boolean {
    const ek = this.keys.get(keyId);
    return ek !== undefined && ek.destroyed;
  }
}
