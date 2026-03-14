/**
 * IEphemeralKey — Common interface for crypto-shredding primitives.
 *
 * F-04: Unifies the contract across EphemeralKey variants without
 * merging implementations. Each variant wraps different key material
 * (Uint8Array vs CryptoKey) for different use-cases.
 *
 * Implementations:
 * - ephemeral-key.ts  (Uint8Array, raw byte shredding — used by pairwise-did)
 * - ephemeral.ts      (CryptoKey, GC-based destruction — used by WalletService)
 */
export interface IEphemeralKey {
  /** Returns true if key material has been irreversibly destroyed. */
  isShredded(): boolean;

  /** Irreversibly destroys key material. Idempotent — safe to call multiple times. */
  shred(): void;
}
