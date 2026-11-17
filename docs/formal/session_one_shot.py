#!/usr/bin/env python3
"""SMT check of an idealized, single-session, linearized transition system.

This is not a model of cryptography, networks, or the complete implementation.
Run with z3-solver 4.15.4.0; see README.md for assumptions and scope.
"""
from z3 import And, Bool, If, Implies, Int, Not, Solver, sat, unsat, get_version_string


def check(name, condition, expected):
    solver = Solver()
    solver.add(condition)
    result = solver.check()
    print(f'{name}: {result}')
    if result != expected:
        raise SystemExit(f'{name}: expected {expected}, got {result}')
    if result == sat:
        print(f'  witness: {solver.model()}')


used, valid_issuer, valid_holder, valid_binding, eligible = (
    Bool(name) for name in ('used', 'valid_issuer', 'valid_holder', 'valid_binding', 'eligible')
)
count = Int('accepted_count')
checks = And(valid_issuer, valid_holder, valid_binding, eligible)
invariant = And(count >= 0, count <= If(used, 1, 0))
accept = And(Not(used), checks)
# One atomic claim consumes the session even if subsequent checks fail.
next_used = True
next_count = count + If(accept, 1, 0)
next_invariant = And(next_count >= 0, next_count <= If(next_used, 1, 0))

print(f'z3 {get_version_string()}')
check('base-invariant-violation', Not(And(0 >= 0, 0 <= 0)), unsat)
check('inductive-invariant-violation', And(invariant, Not(next_invariant)), unsat)
check('accepted-with-failed-check', And(accept, Not(checks)), unsat)
check('replay-accepted-after-consumption', And(used, accept), unsat)

# Mutants demonstrate that checks can expose violations, rather than passing vacuously.
mutant_used = False
mutant_count = If(checks, 1, 0)
mutant_second_accept = And(Not(mutant_used), checks)
check('mutant-unconsumed-replay', And(checks, mutant_count == 1, mutant_second_accept), sat)
mutant_accept = And(Not(used), valid_issuer, valid_holder, eligible)
check('mutant-missing-binding-check', And(mutant_accept, Not(valid_binding)), sat)
check('honest-accept-is-reachable', And(Not(used), checks, accept), sat)
