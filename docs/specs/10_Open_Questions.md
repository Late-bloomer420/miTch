# Open Questions (to resolve)

1. **Credential format + proof system**
   - Which exact credential/proof stack for Phase 0 (SD-JWT VC, BBS+, ZK circuits, etc.)?
   - Trade-offs: verifier complexity vs privacy vs ecosystem adoption.

2. **Issuer integration boundary**
   - How do state providers expose proofs without exporting raw PII?
   - Online query vs pre-issued credential vs hybrid.

3. **Revocation / status checking**
   - Privacy-preserving status checks without correlation.

4. **User consent UX**
   - How to make “service requires X/Y/Z” explicit without dark patterns.
   - How to log local receipts for user review.

5. **Metadata minimization**
   - What exactly is logged server-side and for how long?
   - How to handle abuse monitoring without user profiling?

6. **Recovery**
   - Whether social recovery is required for the product line.
   - Guardian discovery + authentication without central directory.

7. **AI orchestrator integration**
   - Where exactly does policy enforcement sit when an orchestrator calls tools?
   - How to certify tool I/O formats and enforce output redaction.
