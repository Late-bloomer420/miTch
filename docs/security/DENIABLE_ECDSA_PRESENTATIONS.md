# Can an age-check verifier prove the encounter to someone else?

Research proposal for the miTch SD-JWT reference flow. The repository [README](../../README.md) distinguishes its synthetic browser demo from the reference flow, which discloses numeric age. A venue that learns an age can record it. A separate question is whether it can hand another party cryptographic evidence that the issuer endorsed that age in the credential it saw.

## What changes at presentation

Bertram and Lehmann keep ordinary ECDSA issuance. In §4.1 the wallet replaces the transferable issuer signature in the presentation with an OR-proof. One witness comes from a valid issuer signature on the message. The other is the designated verifier’s private key. An honest wallet uses the first. The verifier can generate an indistinguishable transcript using the second, even without a credential. Anyone inspecting that transcript later therefore lacks cryptographic grounds to attribute it to the wallet. A verifier evaluating a live session knows whether it generated the proof itself. This argument depends on authenticating the verifier key and establishing possession of its secret.

The result covers a single transcript. Reusing an issuer signature repeats the curve point R across presentations. Fresh challenges do not remove this correlation. The ordinary key-binding JWT also remains publicly verifiable. The paper’s identity-deniability argument assumes a fresh, anonymous holder key for each single-show credential. Logs, cameras, identifying disclosures and independent receipts can still establish who visited. See §§2 and 4.3.

## Proposed experiment

Use an isolated synthetic wallet/verifier fixture. Keep ordinary issuance as the baseline and define a separate experimental wire format for the verifier. Document the exact signed bytes and how disclosure digests and holder binding are checked after replacing the issuer signature. An ordinary SD-JWT verifier cannot be assumed to accept the replacement. Treat request authentication, consent, replay prevention and attribute minimisation as separate requirements. The proof by itself neither computes an age threshold nor reduces the disclosed age.

| Review gate | Required evidence |
| --- | --- |
| Correct designation | With the same synthetic message and keys, accept both a wallet proof and a verifier simulation. Reject a changed message, substituted verifier key, malformed point or modified proof. Validate the construction and encoding against independent cryptographic review. |
| Authenticated request | Reject an untrusted verifier or one lacking evidence of key possession. Reject a changed audience or nonce and a replay at the presentation entry point. |
| Single use | Race two presentations of the same credential, then retry after a simulated crash. At most one may release a transcript. Use fresh issuer signatures and independent holder keys across successful presentations. |
| Transferable evidence | Inspect captured outbound bytes, verifier logs, receipts and exports with synthetic markers. Fail if any path includes the original signed credential or binds the encounter to an identified holder through separately verifiable evidence. |
| Compatibility | Reject unsupported profiles without silently forwarding the original SD-JWT. Record receiver support and remaining identifying disclosures before considering rollout. |

Start with the evidence inventory on one synthetic age check. Trace what a venue could forward and what a third party could verify independently. That gives the experiment a baseline and can expose a transferable receipt that changing the presentation alone would leave intact.

Source: Magdalena Bertram and Anja Lehmann, [Deniability for Signed Credentials: Revisiting the Authenticated Channel vs. Signed Data Debate in the EUDI Wallet](https://hpi.de/oldsite/fileadmin/user_upload/fachgebiete/lehmann/Publications/deniableECDSA.pdf).
