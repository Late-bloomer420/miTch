# Single-show deniable presentations for ECDSA-signed credentials

Proposed miTch capability, based on Bertram and Lehmann’s designated-verifier construction. The intended guarantee is cryptographic non-transferability of a single presentation transcript.

Research proposal for the miTch SD-JWT reference flow. The repository [README](../../README.md) distinguishes its synthetic browser demo from the reference flow, which discloses numeric age. A venue that learns an age can record it. A separate question is whether it can hand another party cryptographic evidence that the issuer endorsed that age in the credential it saw.

## What changes at presentation

Bertram and Lehmann keep ordinary ECDSA issuance. In §4.1 the wallet replaces the transferable issuer signature in the presentation with an OR-proof. One witness comes from a valid issuer signature on the message. The other is the designated verifier’s private key. An honest wallet uses the first. The verifier can generate an indistinguishable transcript using the second, even without a credential. An observer of a single transcript who does not see the underlying issuer signature cannot distinguish its origin in the paper’s model. A verifier evaluating a live session knows whether it generated the proof itself. This argument depends on authenticating the verifier key and establishing possession of its secret.

The result covers a single transcript. Reusing an issuer signature repeats the curve point R across presentations. Fresh challenges do not remove this correlation. The ordinary key-binding JWT also remains publicly verifiable. The paper’s identity-deniability argument assumes a fresh, anonymous holder key for each single-show credential. Logs, cameras, identifying disclosures and independent receipts can still establish who visited. See §§2 and 4.3.

## Cryptographic assumptions for the profile review

The paper separates two claims. Theorem 1 compares the distribution of one wallet transcript with that of a verifier simulation, provided the observer does not see the underlying ECDSA signature. Include any party that already has the original signature in a separate threat scenario. Theorem 2 concerns an outsider forging an accepted proof on a fresh message. Its argument assumes ECDSA unforgeability under chosen-message attack and discrete-log hardness, and models the Fiat–Shamir hash as a random oracle. The verifier itself is an intended simulator.

For the profile review in [#261](https://github.com/Late-bloomer420/miTch/issues/261), document the following distinctions.

| Mechanism | What reviewers should check |
| --- | --- |
| ECDSA signature | Identify the exact signed bytes and the trusted issuer key. A valid issuer signature authenticates the signed assertion. Establishing a visit, time or holder presence requires separate evidence. |
| OR-proof | Write down the public statement and both secret witnesses. Hiding which witness was used leaves the public inputs visible. Any age threshold requires its own authenticated claim or predicate proof. |
| Nonces | Keep the secret issuer signing scalar, the prover’s secret ephemeral scalars, and the public session nonce distinct. Reusing a signing scalar across distinct message hashes can expose the issuer key. Re-presenting an already signed credential repeats its public point and creates a correlation even with fresh session nonces. |
| Fiat–Shamir challenge | Specify unambiguous encodings, domain separation and all inputs. Identify how the session and intended verifier are bound and checked. Record any departure from the paper for review. |
| Evidence | Positive and negative vectors check implementation behavior. Two accepting examples cannot establish indistinguishability of distributions. Review the argument, its assumptions and what the observer can obtain from other paths. |

Foundations: Dan Boneh and Victor Shoup, *A Graduate Course in Applied Cryptography*, v0.6, §§19.3–19.4 (ECDSA and Sigma protocols), §§19.7–19.8 (OR-proofs and witness independence), §20.3 (non-interactive proofs and Fiat–Shamir). [Textbook](https://toc.cryptobook.us/book.pdf)

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
