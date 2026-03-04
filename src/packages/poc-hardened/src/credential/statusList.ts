/**
 * StatusList2021 — Bitstring-based revocation
 *
 * Issuer publishes a compressed bitstring. Each bit = one credential.
 * 1 = revoked, 0 = active.
 * Verifier downloads entire list, checks locally → issuer can't tell which credential was checked.
 */

import { gzipSync, gunzipSync } from "zlib";

// ─── Publisher (Issuer side) ─────────────────────────────────────

export class StatusListPublisher {
  private bitstring: Uint8Array;
  private listUrl: string;
  private ttlMs: number;

  constructor(capacity: number, listUrl: string, ttlMs: number = 24 * 3600 * 1000) {
    // Each byte holds 8 credential statuses
    this.bitstring = new Uint8Array(Math.ceil(capacity / 8));
    this.listUrl = listUrl;
    this.ttlMs = ttlMs;
  }

  revoke(credentialIndex: number): void {
    const byteIndex = Math.floor(credentialIndex / 8);
    const bitIndex = 7 - (credentialIndex % 8);
    if (byteIndex >= this.bitstring.length) throw new Error("index_out_of_range");
    this.bitstring[byteIndex] |= (1 << bitIndex);
  }

  unrevoke(credentialIndex: number): void {
    const byteIndex = Math.floor(credentialIndex / 8);
    const bitIndex = 7 - (credentialIndex % 8);
    if (byteIndex >= this.bitstring.length) throw new Error("index_out_of_range");
    this.bitstring[byteIndex] &= ~(1 << bitIndex);
  }

  isRevoked(credentialIndex: number): boolean {
    const byteIndex = Math.floor(credentialIndex / 8);
    const bitIndex = 7 - (credentialIndex % 8);
    if (byteIndex >= this.bitstring.length) return false;
    return ((this.bitstring[byteIndex] >> bitIndex) & 1) === 1;
  }

  publish(): StatusList2021 {
    const compressed = gzipSync(Buffer.from(this.bitstring));
    return {
      id: this.listUrl,
      type: "StatusList2021",
      encodedList: compressed.toString("base64"),
      validUntil: new Date(Date.now() + this.ttlMs).toISOString(),
    };
  }

  get url(): string {
    return this.listUrl;
  }
}

// ─── Verifier (Consumer side) ────────────────────────────────────

export interface StatusList2021 {
  id: string;
  type: "StatusList2021";
  encodedList: string;    // base64(gzip(bitstring))
  validUntil?: string;
}

export function checkRevocation(list: StatusList2021, credentialIndex: number): boolean {
  const compressed = Buffer.from(list.encodedList, "base64");
  const bitstring = gunzipSync(compressed);
  const byteIndex = Math.floor(credentialIndex / 8);
  const bitIndex = 7 - (credentialIndex % 8);
  if (byteIndex >= bitstring.length) return false;
  return ((bitstring[byteIndex] >> bitIndex) & 1) === 1;
}
