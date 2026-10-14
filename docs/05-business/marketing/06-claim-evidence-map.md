# AskMI public claim → scoped evidence map

**Updated:** 2026-10-14. Current executable baseline: `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`.
[Current register](../../security/REPO_EVIDENCE_STATUS_2026-10-14.md) controls claim language;
[dated record](../../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) controls what was tested.

| Allowed wording | Evidence | Limitation that must accompany it |
|---|---|---|
| Repository-tested policy input/layer/downgrade controls | policy-engine tests; #125 scoped fix | Not all routes invoke all controls; #170 open |
| Issuer-authenticated SD-JWT and selective disclosure components | #132/#135/#137 and internal tests | Demo discloses numeric age; HTTP eligibility/session/scope incomplete |
| Pairwise DID and legacy single-use pool components | #86–#94 tests | No end-to-end unlinkability; real SD-JWT lifecycle #171 open |
| Locally signed predicate result | predicates evaluator + signature verifier | Not a cryptographic proof of correct hidden-credential derivation |
| Tamper-evident local audit and minimised Tier-2 schema | audit-log helpers, #81 schema/tests | Actual sinks/TTL/durability #172/F-19 open; not universal PII-free logs |
| Wrapper-owned key buffer overwritten/API reuse denied | named key-wrapper tests | Callback copies, WebCrypto/runtime copies and timeout cancellation remain; GAP-1 |
| Requested/authorised/withheld reference UI | DataFlow components/tests | UI text must not create a proof, privacy or cleanup guarantee |
| 10 manifest PASS / 2 RESIDUAL on the dated run | evidence manifest and 14 October record | Manifest excludes active HTTP/real single-use findings; source/file hash #173 open |

Do not claim “never raw data/PII”, “zero identity custody on every server”, “all ephemerals erased”,
“untrackable”, “certified-ready”, “LoA High”, “fully compliant” or percentage readiness.
No official-wallet interoperability, independent security review, customers or completed buyer gate is established by this map.
Public demos and plans are synthetic/illustrative or proposed, not implementation evidence.
