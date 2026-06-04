import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Synchronous, isomorphic SHA-256 returning a lowercase hex string.
 *
 * Uses @noble/hashes (pure JS, the same primitive shared-crypto relies on) so the
 * result is always a real 64-character SHA-256 digest — in Node, browsers, and
 * workers alike. This deliberately replaces earlier `node:crypto`-only helpers that
 * either threw in the browser or silently fell back to a non-cryptographic 32-bit
 * hash while still being named `sha256`. The audit `verifierHash` and the
 * DecisionCapsule integrity fields depend on this being a genuine SHA-256.
 */
export function sha256Hex(data: string): string {
  return toHex(sha256(new TextEncoder().encode(data)));
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}
