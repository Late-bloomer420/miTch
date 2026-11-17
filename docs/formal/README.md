# Single-session safety: idealized SMT model

This artifact is a starting point for [#197](https://github.com/Late-bloomer420/miTch/issues/197), not a formal verification of AskMI or an implementation of Tamarin. It models one already-created session with an atomic claim followed by abstract Boolean checks. It does not close #197 or #97, authorize a release, or establish the Entire Brain release gate.

## Assumptions and abstraction

The single session is never reset or recreated, session identifiers are not reused, and each attempt's claim is linearizable and consumed even when checks fail. An idealized serialized step combines claim and completion; expiry, deletion, crash, persistence, multi-process stores, asynchronous overlap and result delivery are not modeled. `valid_issuer`, `valid_holder`, `valid_binding`, and `eligible` are independent Boolean inputs standing for correct checks, not evidence that cryptography or policy checks implement them correctly. The model has no attacker-controlled cryptographic terms, key compromise, issuer-verifier collusion, credential format or selective-disclosure semantics. It proves neither unlinkability, zero knowledge nor resistance to impersonation or trust bypass in the implemented protocol.

The intended mapping is the in-memory `consume` in `src/packages/connect/src/core/session-store.ts` and `completeSession` in `src/packages/connect/src/core/verifier.ts`, source `58d0af9df2fa13f8f38359546c98efc54df542a2`. That mapping is a review hypothesis, not a verified refinement. The actual implementation separates asynchronous validation from final update, supports expiration/deletion and injectable stores/callbacks. Those differences must be modeled and verified before extrapolating the abstract invariant to the code. The issuer-key resolver and verification callbacks require independent review.

## Property and proof obligations

Let `used` indicate whether the one session has been consumed and `count` the number of accepted attempts. The invariant is `count >= 0 ∧ count <= (if used then 1 else 0)`. Initially `used = false` and `count = 0`. One abstract step sets `used = true`, and increases `count` exactly when the prior session was unused and all checks were true. Z3 checks that neither the base case nor any invariant-preserving transition can violate the invariant. By induction over the modeled transitions, no modeled execution can accept more than once. It also checks that an accepted attempt has all abstract checks true and that a consumed session cannot accept again.

The model additionally requires a reachable honest acceptance and counterexamples for two mutations: failure to consume and omission of the binding check. This helps expose vacuous assertions; it does not prove that the mutations correspond to actual implementation defects. Solver `unsat` is conditional on the model and solver correctness, not a security certificate.

## Reproduce

Use Python 3 and `z3-solver==4.15.4.0` in an isolated environment:

```sh
python -m pip install z3-solver==4.15.4.0
python docs/formal/session_one_shot.py
```

Expected: four `unsat` violation checks, two `sat` mutant witnesses, and a `sat` reachability witness. Nonmatching outcomes or solver errors cause a nonzero exit. Review the script and models before relying on the result.

## Further work

- Map transitions to the code and model interleaved in-flight operations, expiry, cleanup, recreation, and failure paths; prove or find counterexamples for each store implementation.
- Use a symbolic protocol verifier for issuer signatures, holder binding, nonce/audience and trust assumptions as described by #197; independently review the model.
- Link exact code revision and negative integration tests to each property. Check actual wallet interoperability and security review separately.
