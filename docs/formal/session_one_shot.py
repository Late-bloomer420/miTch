#!/usr/bin/env python3
"""SMT check of an idealized, single-session, linearized transition system.

This is not a model of cryptography, networks, or the complete implementation.
Run with z3-solver 4.15.4.0; see README.md for assumptions and scope.
"""
from z3 import (
    And,
    Bool,
    BoolVal,
    If,
    Int,
    IntVal,
    Not,
    Solver,
    get_version_string,
    sat,
    substitute,
    unsat,
)


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
all_checks = And(valid_issuer, valid_holder, valid_binding, eligible)
safe_invariant = And(count >= 0, count <= If(used, 1, 0))
honest_accept = And(Not(used), all_checks)
# One atomic claim consumes the session even if subsequent checks fail.
honest_next_used = BoolVal(True)


def violations(accept, next_used, invariant):
    """Return each property's violation formula for one transition system."""
    next_count = count + If(accept, 1, 0)
    return {
        'base': Not(substitute(invariant, (used, BoolVal(False)), (count, IntVal(0)))),
        'inductive': And(
            invariant,
            Not(substitute(invariant, (used, next_used), (count, next_count))),
        ),
        'accept-without-all-checks': And(accept, Not(all_checks)),
        'accept-after-consumption': And(used, accept),
    }


print(f'z3 {get_version_string()}')

for name, violation in violations(honest_accept, honest_next_used, safe_invariant).items():
    check(f'honest-{name}', violation, unsat)

# Each mutant changes the model, and the same property check must then find a counterexample.
mutants = {
    'no-consume': (honest_accept, used, safe_invariant, 'inductive'),
    'missing-binding-check': (
        And(Not(used), valid_issuer, valid_holder, eligible),
        honest_next_used,
        safe_invariant,
        'accept-without-all-checks',
    ),
    'ignores-consumed-session': (
        all_checks,
        honest_next_used,
        safe_invariant,
        'accept-after-consumption',
    ),
    'invariant-excludes-initial-state': (
        honest_accept,
        honest_next_used,
        And(count >= 1, count <= If(used, 1, 0)),
        'base',
    ),
}
for name, (accept, next_used, invariant, detected_by) in mutants.items():
    check(f'mutant-{name}', violations(accept, next_used, invariant)[detected_by], sat)

check('honest-accept-is-reachable', And(Not(used), count == 0, honest_accept), sat)
