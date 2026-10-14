# AskMI requirement-level traceability — incomplete, externally unvalidated

**Updated:** 2026-10-14. **Executable baseline:** `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`.
This is engineering evidence navigation, not a legal interpretation or certification/compliance matrix.
The [June checklist](archive/EUDI_CIR_MATRIX_2026-06-02.md) is historical; its 98%/100%, LoA High and FCAF-readiness conclusions are withdrawn as current claims.
Complete current official requirement/role/profile traceability is still an open Wave-0/2 task under #142.

| Requirement/control concern | Source/profile boundary | Current implementation/evidence | Status / owner |
|---|---|---|---|
| Issuer signature and disclosure digests | Repo SD-JWT implementation; exact official profile unvalidated | #132/#135/#137, internal tests and dated ADOPT observation | Implemented primitives; no whole-profile conformance |
| Holder proof | SD-JWT KB-JWT and caller-configured verifier APIs | Signature/aud/nonce primitives exist; expected HTTP nonce reconstructed from input | Partial active integration; #170 |
| Session freshness / replay | Active `/oid4vp-present` HTTP route | Identical signed token accepted twice; changed nonce/state accepted | OPEN P0 #170 |
| Eligibility / minimisation | Current numeric-age Connect design | Signed age=12 and excess name accepted by demo route | OPEN P0 #170; #97 profile decision |
| Single-use/unlinkability | Legacy B+C versus stored SD-JWT path | Legacy pool exists; stored singleUse credential reused | OPEN #171; not universal unlinkability |
| Audit integrity | Local hash-chain/signature helpers | Named unit/adversarial tests | Scoped implementation; no global WORM/durability |
| Audit/export minimisation and retention | Tier-2 schema vs local history/actual outputs | Helper tests; runtime sink/TTL integration not established | OPEN #172; F-19 |
| Memory/key erasure | JS/WebCrypto runtime | Owned buffers/API controls; copies/callback continue after timeout | GAP-1; no physical RAM/remote erasure assurance |
| Trust / RP registration | JSON trust-list demo vs ETSI/current source registry | Internal prototype; official-profile chain/registration matrix absent | OPEN #142 Wave 2 |
| Native wallet / protocol parity | Dated EUDI source registry, role-specific profile | No published official Android/iOS/conformance artifacts establishing current AskMI profile | OPEN #97/#142 Waves 1–4 |
| Independent security assurance / LoA / CC | Separate external evaluation | No independent review/certification result recorded | GAP-4; do not claim LoA High/EAL4+ readiness |
| Deployment / privacy operations | Actual target topology and jurisdiction | Docs/runbooks are design input; exercised controls not established here | OPEN #142 Waves 3/4 |

Every completed future row needs source/version, AskMI role/profile, implementation commit, negative/integration test,
external artifact where applicable, owner, date and residuals. Internal test percentages must not replace those fields.
[Current findings](../security/REPO_EVIDENCE_STATUS_2026-10-14.md), [dated evidence](../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md),
[official-source planning registry](../eudi/EUDI_SOURCE_BASELINE.md).
