# AskMI: use cases and go-to-market brainstorm

Date: 11 September 2026.

Status: initial product and commercial hypotheses from the discussion. No customer demand, pricing, credential availability or market advantage has been validated. This is not an approved implementation plan.

Related assessment: [EUDI architecture and issuer-role report](../compliance/EXTERNAL_DESK_AUDIT_EUDI_2026-09-11.md).

## 1. Working hypothesis

Sell AskMI as a way to make trustworthy access decisions with less document handling. Start as a verifier and integration layer. Consider new attestation issuance when customers need a reusable assertion that other organisations will accept.

The architecture should support multiple use cases, while the first commercial offer addresses one concrete workflow. Age verification remains a reference scenario rather than the entire product.

Education, professional qualifications, banking and travel already feature in the EUDI ecosystem. These are potential ecosystems to join, not evidence of untouched markets. See the [Commission's pilot overview](https://digital-strategy.ec.europa.eu/en/policies/eudi-wallet-implementation).

## 2. Two roles, two businesses

### Role A: verifier and integration provider

AskMI helps a relying party request and verify original credential evidence, apply its business rules and produce a scoped internal decision. The existing issuer remains responsible for the credential assertion.

Potential product: customer-deployed SDK or service with wallet integration, verification, policy configuration and limited operational records.

Potential revenue hypothesis: paid integration followed by a recurring software and support licence.

### Role B: issuer of new attestations

AskMI makes a new assertion under its own issuer identity for other organisations to rely on. The product must establish why those organisations should accept AskMI's assertion, what it means, and how it is maintained, expired or revoked.

This route requires a separate issuer-role assessment, including the potential obligations of non-qualified or qualified attestation provision. Re-signing does not automatically preserve the original issuer's legal status or authority. See the related audit for the legal distinction and sources.

Potential revenue hypothesis: contracts for operating an accepted attestation scheme or issuance service. Pricing is unresolved and should follow evidence of demand and responsibility.

### Important alternative: supply issuance technology

An association, employer or other authorised organisation could issue its own assertions using AskMI software. The organisation may be the issuer while AskMI supplies the technology. Contracts and the actual operating model must identify who makes and stands behind each assertion; a software label alone does not determine legal roles.

## 3. Candidate use cases

These are proposals for discovery interviews, not confirmed customer needs or claims that every necessary credential is available.

| Use case                          | AskMI as verifier layer                                                | AskMI as issuer                                                                          | Potential buyer                                       |
| --------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Contractor onboarding             | Verify identity, training and qualifications against site requirements | Issue a time-limited attestation that specified onboarding checks were completed         | Contractor-management platform or industrial operator |
| Professional access               | Verify qualifications and current entitlement before granting access   | Attest membership or authorisation that the issuer is actually empowered to grant        | Professional association or sector software provider  |
| Education and membership benefits | Verify eligibility without unnecessary identity-document collection    | Issue a reusable benefit entitlement under an agreed scheme                              | Institution, membership platform or benefits operator |
| Equipment rental                  | Verify required identity/licence attributes and apply rental policy    | Issue a reusable checks-completed attestation accepted by participating rental companies | Rental software vendor or rental network              |

Issuance is commercially interesting only if another organisation needs and accepts the new attestation. If the result is only needed for the recipient's immediate access decision, internal verification may be sufficient.

## 4. Leading candidate: contractor onboarding

Workflow hypothesis to investigate:

> Before a contractor can enter a site, staff must check several requirements. They collect documents, review them manually and repeat the process for renewals or new engagements.

AskMI could verify available credentials, apply the site's requirements, identify missing evidence and retain appropriately limited records. The first investigation must establish whether this process is frequent, expensive and supported by accessible credential sources.

Suggested initial positioning:

> Check contractor eligibility without building your own wallet integration or collecting unnecessary documents.

Why explore it first:

- Several credential types give the abstraction layer a concrete purpose.
- Recurring checks could create continuing value beyond initial onboarding.
- A specific site or platform provides a bounded pilot workflow.
- The customer can potentially measure manual work and completion time.

Main risks and unknowns:

- Suitable credentials may not exist or be available to the intended users.
- Existing access and contractor-management systems may be difficult to integrate.
- Buyers may consider their present process adequate.
- Responsibility for incorrect eligibility decisions needs a clear allocation.
- Reusable checks can become stale; acceptance must account for changed qualifications, policies and status.

## 5. Market-entry options

| Strategy                                | Initial offer                                                        | Main difficulty                                                               |
| --------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Direct customer pilot                   | Solve one organisation's onboarding workflow                         | Bespoke work can consume the product                                          |
| Partner with a vertical software vendor | Embed AskMI in software already serving the target workflow          | Integration work and dependence on the partner                                |
| Create an attestation network           | Establish acceptance of AskMI-issued assertions across organisations | Recruit evidence sources and accepting organisations while establishing trust |

Initial recommendation: explore a vertical software vendor partnership with one participating customer. The vendor already serves the workflow; AskMI contributes verification and policy capabilities. This recommendation remains conditional on access to a suitable partner and evidence of buyer pain.

Avoid starting with a broad promise of universal compliance or universal credential acceptance. Define the supported workflow, evidence sources and responsibility precisely.

## 6. First commercial experiment

1. Interview five potential buyers about their current checks, costs, delays and failure cases.
2. Select one workflow with accessible credential sources and a willing pilot customer.
3. Offer a fixed-scope, paid integration pilot.
4. Measure manual reviews avoided, completion time, unnecessary data collected and support effort against the existing process.
5. If the pilot creates measurable value, test a recurring software and support licence.

Before the pilot, agree the baseline, measurement method, success criteria and who decides whether to purchase. No numerical target or price has been agreed yet.

Continue only if the customer has a real problem, usable evidence sources and a credible path to payment. Reconsider the workflow if it depends on unavailable credentials, removes no meaningful work or requires repeated bespoke integrations without reusable value.

## 7. Gate for the issuer route

Postpone AskMI-issued credentials until there is evidence of this demand:

> We need this result to be reusable elsewhere, and these organisations will accept it.

Before proceeding, identify the assertion, its evidence, authorised issuer, intended recipients, acceptance agreements, validity period and status lifecycle. Complete the issuer-role and legal assessment described in the audit. Neither willingness to pay nor technical validity alone establishes permission or qualified status.

## 8. Next discovery question

Which potential buyers can the project realistically reach through work, existing contacts or partners?

Access to buyers should strongly influence the first market choice. No answer, target country, partner, pricing or final market selection was established in this brainstorm.
