/**
 * SameValueZero, the equality JavaScript `Set` and `Map` use: like `===`,
 * except that NaN equals NaN. All element comparisons in this package use it,
 * so property checks agree with set membership.
 */
export function sameValueZero(a: unknown, b: unknown): boolean {
  return a === b || (a !== a && b !== b);
}
