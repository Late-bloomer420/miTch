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
 * This module is pure and storage-agnostic: it decides WHICH member to use and
 * tracks consumption. Wiring into WalletService storage is a later increment.
 *
 * Honesty boundary: this delivers unlinkability through NON-REUSE, not through
 * cryptographic multi-show unlinkability (that would be BBS+, deferred).
 */

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
