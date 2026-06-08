/**
 * Single-Use Credential Wiring — honest flag + consumption (Proof-Randomization, U-12)
 *
 * Part of the Unlinkability "Phase 2 — Randomized Proofs" sprint
 * (see docs/tasks/SPRINT_PROOF_RANDOMIZATION.md, Review 1 option A).
 *
 * Pure, storage-agnostic helpers that bridge stored-credential metadata to:
 *   1. the `single_use_credential` audit flag recorded on VP_GENERATED, and
 *   2. the consumption transition that prevents a single-use credential from
 *      ever being presented twice (fail-closed non-reuse).
 *
 * Relationship to credential-pool.ts: that module decides WHICH member of a
 * batch-issued pool to present (needs batch issuance to populate the pool).
 * THIS module decides the honest flag + consume transition for whatever the
 * policy engine already selected. The two compose; neither replaces the other.
 *
 * Honesty boundary: the flag asserts only that a presented credential is marked
 * single-use AND is consumed on use — i.e. real NON-REUSE. It does NOT claim
 * cryptographic multi-show unlinkability (that would be BBS+, deferred).
 */

import type { StoredCredentialMetadata } from '@askmi/shared-types';

/** Just the fields these helpers reason about, so callers can pass partials. */
type SingleUseFields = Pick<StoredCredentialMetadata, 'singleUse' | 'consumedAt'>;

/**
 * True when at least one presented credential is single-use. `null`/`undefined`
 * entries (skipped requirements without a selected credential) are ignored.
 */
export function isSingleUsePresentation(
  metas: Array<Pick<StoredCredentialMetadata, 'singleUse'> | null | undefined>
): boolean {
  return metas.some((m) => m?.singleUse === true);
}

/** A single-use credential that has not yet been consumed still needs consuming. */
export function needsConsumption(meta: SingleUseFields): boolean {
  return meta.singleUse === true && !meta.consumedAt;
}

/**
 * Return metadata marking a single-use credential consumed at `consumedAt`.
 * Immutable and idempotent: a reusable credential is returned unchanged (same
 * reference); an already-consumed credential keeps its original `consumedAt`.
 */
export function markConsumed<T extends StoredCredentialMetadata>(meta: T, consumedAt: string): T {
  if (meta.singleUse !== true || meta.consumedAt) return meta;
  return { ...meta, consumedAt, status: 'dispensed' };
}

/**
 * Drop already-consumed single-use credentials from a selection set. Reusable
 * credentials and still-unused single-use credentials are kept. Fail-closed:
 * a consumed single-use credential becomes invisible to the policy engine, so
 * it can never be re-presented.
 */
export function selectablePresentationCredentials<T extends StoredCredentialMetadata>(
  metas: T[]
): T[] {
  return metas.filter((m) => !(m.singleUse === true && !!m.consumedAt));
}
