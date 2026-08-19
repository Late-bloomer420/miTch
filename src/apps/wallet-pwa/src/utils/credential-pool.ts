/**
 * Credential Pool — Single-Use Presentation Selection (Proof-Randomization, U-12)
 *
 * Part of the Unlinkability "Phase 2 — Randomized Proofs" sprint
 * (see docs/tasks/SPRINT_PROOF_RANDOMIZATION.md, Review 1 option C).
 *
 * A "pool" is a set of batch-issued credentials that share the same logical
 * identity (same type/issuer) but each carry a distinct holder binding. By
 * presenting a different, previously-unused member on each interaction, the
 * wallet avoids re-using one credential's stable issuer signature / cnf holder
 * key as a cross-verifier correlator.
 *
 * The pure core decides WHICH member to use and tracks consumption. The wallet
 * bridge `selectPoolMembersForPresentation` (bottom of file) maps stored
 * credential metadata onto that core so WalletService can narrow each pool to a
 * single member before policy evaluation (Increment 2 wiring).
 *
 * Honesty boundary: this delivers unlinkability through NON-REUSE, not through
 * cryptographic multi-show unlinkability (that would be BBS+, deferred).
 */

import type { StoredCredentialMetadata } from '@askmi/shared-types';

/** How a pool is consumed. */
export type CredentialPoolPolicy = 'single_use' | 'reuse';

/** One batch-issued member of a credential pool. */
export interface CredentialPoolMember {
  /** Stored credential id in the wallet. */
  id: string;
  /** ISO-8601 issuance timestamp; used for deterministic FIFO ordering. */
  issuedAt: string;
  /** ISO-8601 timestamp when consumed, or null while still unused. */
  usedAt: string | null;
}

/** Result of asking the pool for the next member to present. */
export interface CredentialPoolSelection {
  /** The chosen member, or null when none can be presented. */
  member: CredentialPoolMember | null;
  /**
   * True only when a single_use pool HAD members but all are consumed.
   * An empty pool is not "exhausted" — there was simply nothing to begin with.
   */
  exhausted: boolean;
}

/** Aggregate counts for UI / diagnostics. */
export interface CredentialPoolStats {
  total: number;
  used: number;
  available: number;
}

/**
 * Deterministic FIFO ordering: oldest issuance first, id as a stable tiebreaker.
 * Returns a sorted copy; never mutates the input.
 */
function orderedByIssuance(members: CredentialPoolMember[]): CredentialPoolMember[] {
  return [...members].sort((a, b) => {
    if (a.issuedAt !== b.issuedAt) return a.issuedAt < b.issuedAt ? -1 : 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

/**
 * Select the member to present next.
 *
 * - `single_use`: the oldest UNUSED member; `exhausted: true` when members
 *   exist but are all consumed (fail-closed — never silently re-uses).
 * - `reuse`: the oldest member regardless of usage (legacy behavior); never
 *   exhausted while any member exists.
 */
export function selectPoolMember(
  members: CredentialPoolMember[],
  policy: CredentialPoolPolicy = 'single_use'
): CredentialPoolSelection {
  const ordered = orderedByIssuance(members);

  if (policy === 'reuse') {
    return { member: ordered[0] ?? null, exhausted: false };
  }

  const unused = ordered.find((m) => m.usedAt === null);
  if (unused) {
    return { member: unused, exhausted: false };
  }
  // No unused member: exhausted only if the pool was non-empty to begin with.
  return { member: null, exhausted: ordered.length > 0 };
}

/**
 * Return a new member list with `id` marked used at `usedAt`.
 * Immutable: the input array and its members are not modified. An already-used
 * member keeps its original `usedAt` (consumption is idempotent). An unknown id
 * leaves the list unchanged.
 */
export function markMemberUsed(
  members: CredentialPoolMember[],
  id: string,
  usedAt: string
): CredentialPoolMember[] {
  return members.map((m) =>
    m.id === id && m.usedAt === null ? { ...m, usedAt } : { ...m }
  );
}

/** Count totals for a pool. */
export function poolStats(members: CredentialPoolMember[]): CredentialPoolStats {
  const used = members.reduce((n, m) => (m.usedAt !== null ? n + 1 : n), 0);
  return { total: members.length, used, available: members.length - used };
}

// --- Wallet bridge (Increment 2) --------------------------------------------

/**
 * Narrow a presentation selection set so each batch-issued pool (grouped by
 * `poolId`) contributes exactly ONE member — the oldest unused one, per
 * `selectPoolMember(single_use)`. This realizes the pool's non-reuse purpose:
 * without it, all unused members of a pool stay visible to the policy engine
 * and the stable per-member holder binding could leak across verifiers.
 *
 * - Standalone credentials (no `poolId`) pass through unchanged.
 * - A fully-consumed pool contributes nothing (fail-closed non-reuse).
 * - Pure: the input is never mutated; output preserves input order with the
 *   non-selected pool members removed.
 *
 * Compose after `selectablePresentationCredentials` (which drops already-
 * consumed single-use credentials) — the two together give: consumed members
 * invisible, and each remaining pool reduced to one presentable member.
 */
export function selectPoolMembersForPresentation<T extends StoredCredentialMetadata>(
  metas: T[]
): T[] {
  const membersByPool = new Map<string, CredentialPoolMember[]>();
  for (const m of metas) {
    if (!m.poolId) continue;

    const member: CredentialPoolMember = {
      id: m.id,
      issuedAt: m.issuedAt,
      usedAt: m.consumedAt ?? null,
    };
    const members = membersByPool.get(m.poolId);
    if (members) {
      members.push(member);
    } else {
      membersByPool.set(m.poolId, [member]);
    }
  }
  if (membersByPool.size === 0) return metas.slice();

  const survivingPooledIds = new Set<string>();
  for (const members of membersByPool.values()) {
    const chosen = selectPoolMember(members, 'single_use').member;
    if (chosen) survivingPooledIds.add(chosen.id);
  }

  return metas.filter((m) => !m.poolId || survivingPooledIds.has(m.id));
}
