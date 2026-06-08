/**
 * Ephemeral Holder Binding (Proof-Randomization, U-11)
 *
 * Part of the Unlinkability "Phase 2 — Randomized Proofs" sprint
 * (see docs/tasks/SPRINT_PROOF_RANDOMIZATION.md, Review 1 option B).
 *
 * Standard SD-JWT VC binds a credential to one holder key via the `cnf` claim.
 * Re-presenting the same credential therefore re-uses the same holder public key
 * as a stable cross-verifier correlator. To make batch-issued credential members
 * unlinkable, each member must carry its OWN holder key: this helper produces a
 * fresh P-256 holder binding so the issuer can embed a distinct `cnf` per member.
 *
 * Composes existing primitives (`generateKeyPair`, `buildCNFClaim`); the private
 * key is non-extractable (cannot be exfiltrated) yet can still sign the KB-JWT.
 */

import { generateKeyPair } from './keys';
import { buildCNFClaim, type CNFClaim } from './sd-jwt-vc';

export interface HolderBinding {
  /** Fresh per-member holder key pair (private key is non-extractable). */
  keyPair: CryptoKeyPair;
  /** Confirmation claim carrying the holder public JWK, for embedding at issuance. */
  cnf: CNFClaim;
}

/**
 * Generate a fresh ephemeral holder binding.
 *
 * Each call yields an independent P-256 holder key. Issuing a batch of credential
 * members each with its own binding means no two members share a holder key, so a
 * single-use presentation flow (see credential-pool) is not linkable by `cnf`.
 */
export async function generateHolderBinding(): Promise<HolderBinding> {
  const keyPair = await generateKeyPair();
  const cnf = await buildCNFClaim(keyPair.publicKey);
  return { keyPair, cnf };
}
