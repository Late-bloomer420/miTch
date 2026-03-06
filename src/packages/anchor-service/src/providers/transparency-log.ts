/**
 * @module @mitch/anchor-service/providers/transparency-log
 *
 * G-09: L2/Blockchain anchoring stub.
 *
 * TransparencyLogAnchorProvider — stub implementation for anchoring Merkle roots
 * to an IETF-compatible Transparency Log (RFC 9162 / Rekor-compatible API).
 *
 * ## Status: STUB
 * Implements the AnchorProvider interface. Does NOT make real HTTP calls.
 * Wire up a real Rekor client or RFC 9162 API to activate production anchoring.
 *
 * ## Integration path (production):
 * 1. Replace `_simulateLogEntry` with POST to `{baseUrl}/api/v1/log/entries`
 * 2. Verify the returned signed tree head (STH) against the log's public key
 * 3. Persist the inclusion proof for offline verification
 */

import type { Hex32, AnchorRef } from '@mitch/shared-types';
import type { AnchorProvider } from '../types.js';

export interface TransparencyLogConfig {
  /** Base URL of the transparency log (e.g. 'https://rekor.sigstore.dev') */
  baseUrl: string;
  /** Log name for receipts (e.g. 'sigstore/rekor', 'mitch/tlog-v1') */
  logName: string;
}

/**
 * Stub implementation of AnchorProvider for IETF Transparency Logs.
 *
 * In production, this would POST the Merkle root as a Rekor/RFC 9162 entry,
 * receive a log inclusion proof, and return the log entry ID as the AnchorRef.
 */
export class TransparencyLogAnchorProvider implements AnchorProvider {
  private config: TransparencyLogConfig;
  private logIndex = 0;

  constructor(config: TransparencyLogConfig) {
    this.config = config;
  }

  /**
   * Publish a Merkle root to the transparency log.
   *
   * @param root - SHA-256 Merkle root of the decision batch
   * @param meta - Batch metadata included in the log entry body
   * @returns AnchorRef with simulated log entry UUID and timestamp
   *
   * @stub Replace the body with a real HTTP POST to the log API.
   */
  async publishRoot(
    root: Hex32,
    meta: { batchId: string; count: number }
  ): Promise<AnchorRef> {
    // STUB: simulate log entry creation
    const entry = this._simulateLogEntry(root, meta);

    return {
      ref: entry.entryUUID,
      timestamp: entry.integratedTime * 1000, // convert Unix seconds → ms
      ...({
        logName: this.config.logName,
        logIndex: entry.logIndex,
        batchId: meta.batchId,
        leafCount: meta.count,
        // In production: signedEntryTimestamp (SET), inclusionProof, logID
      } as Record<string, unknown>),
    };
  }

  /**
   * STUB: simulate a transparency log entry.
   * In production: the real entry UUID comes from the log API response.
   */
  private _simulateLogEntry(
    root: Hex32,
    _meta: { batchId: string; count: number }
  ): { entryUUID: string; logIndex: number; integratedTime: number } {
    const logIndex = this.logIndex++;
    const integratedTime = Math.floor(Date.now() / 1000);
    // Rekor-style UUID: 24 hex chars derived from root
    const entryUUID = `${root.slice(0, 16)}${logIndex.toString(16).padStart(8, '0')}`;

    return { entryUUID, logIndex, integratedTime };
  }
}
