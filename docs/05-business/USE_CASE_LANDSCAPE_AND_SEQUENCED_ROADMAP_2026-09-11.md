# AskMI / miTch: expanded use-case landscape and sequenced roadmap

Date: 2026-09-11
Status: research-backed strategic proposal; not certification, a legal opinion, or an approved delivery backlog.
Audience: founders, engineering, prospective domain partners and regulatory advisers.

## 1. Decision in brief

**Build a trustworthy, RP-deployed verification and policy integration product first. Choose its first vertical through evidence, not by excluding sectors that the EU already discusses. Keep issuer operations as a separate, later business decision.**

This review covers **72 distinct workflows across nine groups**, rates both roles, and orders their investigation and conditional delivery. It does not claim to enumerate every imaginable application or prove demand. Most opportunities are new to our previous shortlist, not inventions without competitors.

The earlier shortlist was too narrow. In particular, EU involvement in travel is a reason to investigate compatibility and customers, not a reason to avoid travel. Standards and pilots do not supply every hotel, rental operator or industry software vendor with a working integration.

Three tracks deserve immediate **customer and credential-supply discovery**:

1. **Vehicle rental:** concrete, multi-credential workflow with an operational buyer; depends on available, accepted driving-licence credentials.
2. **Hotel check-in:** identity-to-property-management integration; depends on country-specific registration requirements and actual wallet access.
3. **Learning, student status and professional credentials:** several related buyers and reusable verification workflows; depends on participating issuers and format compatibility.

Contractor onboarding remains a candidate, not the predetermined winner. Business mandates and data-space access deserve serious medium-term investigation. Border control, payment execution, clinical decisions and general-purpose agent delegation are not sensible first deployments.

**Do not implement all 72 indiscriminately.** Investigate the landscape, select a funded first workflow, prove the shared core, then implement successive workflows only when their gates pass.

## 2. Scope, evidence and limits

This document extends, rather than silently replaces:

- [Earlier brainstorming](USE_CASES_AND_GTM_BRAINSTORM_2026-09-11.md).
- [External desk audit and issuer-role analysis](../compliance/EXTERNAL_DESK_AUDIT_EUDI_2026-09-11.md).
- [Authoritative backlog](../BACKLOG.md), which is not changed by this proposal.

Research includes Commission manuals, legislation, pilot and standards publications, and vendor documentation. Sources were consulted on 2026-09-11. An official manual establishes a described workflow, **not** universal credential availability, national acceptance, certification or paying demand.

Important evidence hygiene:

- The Commission index spans identity, pseudonyms, signatures, driving, proximity, payments, age, travel, parking, disability, education, prescriptions, health insurance, representation, tickets, vehicle registration, warnings, student status and bank onboarding. Some entries have uneven publication status. [S01]
- WE BUILD explicitly covers business onboarding, representation, skills, transport, data spaces, invoicing and banking/payment workflows. These are project use cases, not proof of completed nationwide services. [S07]
- The driving-licence manual contains an outdated expectation about directive adoption. Directive (EU) 2025/2205 is the subsequent legal text; availability must be checked separately. [S02][S03]
- The EWC travel-booking PDF link redirected to its homepage, and the large POTENTIAL brochure could not be retrieved in full. Neither is used as reviewed evidence here.
- No customer interviews, paid-pilot commitments, procurement budgets, country-specific legal opinions or live wallet interoperability tests were completed in this research.
- No market-size or revenue forecasts are invented. Scores below are analyst judgments, not measured probabilities.
- No claim is made that the software currently meets the trust requirements. The prior audit found material blockers.

### Evidence labels

- **D:** workflow directly documented by an official institution or standards body; not a deployment claim.
- **P:** pilot/project or industry proof-of-concept evidence.
- **H:** our proposed extension of a documented workflow; customer and technical validation required.
- **X:** exploratory/high-uncertainty proposition, not a near-term product commitment.

A label applies to the workflow, not automatically to our proposed implementation. Sources accompanying H/X rows are background, not evidence that AskMI's exact product exists or is demanded.

## 3. The two roles and the trust boundary

| Question                           | V: verification/integration software                              | I: AskMI-operated attestation issuer                                                                  |
| ---------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| What is sold?                      | Tools for an RP to validate presentations and apply its policy    | A new statement that other parties rely on                                                            |
| Who speaks for the original facts? | Original issuer; AskMI must preserve and verify its proof         | Original issuer still speaks for its facts; AskMI speaks only for its own new assertion               |
| Typical output                     | Purpose-bound decision for the requesting RP                      | Separately typed attestation with its own issuer, scope, expiry and status                            |
| Core commercial advantage to prove | Easier vertical integration and dependable operation              | Valuable evidence/authority plus an accepting network                                                 |
| Additional dependency              | RP onboarding, accepted credentials, compliant processing         | Authority to assert, relying-party acceptance, issuance lifecycle and applicable trust-service duties |
| Main trap                          | Claiming an API result has the original credential's legal status | Re-signing copied facts and implying inherited government or qualified status                         |

Providing issuer software to a university or employer is another deployment model: **the institution can remain the issuer**. It is not automatically AskMI operating an issuing service. The I scores below concern AskMI as issuer, not merely selling issuance tooling.

Signing a holder presentation is not the same as issuing an attribute attestation. Changing signed credential contents normally breaks the original proof. A new AskMI-signed assertion does not inherit the source credential's legal effects. Whether an output constitutes a regulated service depends on substance and operation, not its JSON field name. Non-qualified trust services can carry obligations too; qualification and wallet certification are separate assessments. [S24][S25]

Architecture recommendation, subject to profile-specific validation:

**Certified wallet and user approval → RP-bound presentation → RP-deployed verifier → local policy decision → business application.**

A REST interface can serve developers. It must not conceal the actual requesting party, bypass the wallet's required user controls, export holder keys, or turn the mediator into an undisclosed identity broker. User approval to disclose and the recipient's GDPR lawful basis are separate questions; the latter is not automatically consent. [S24][S26]

Do not label every signed receipt an EAA or assume it is outside regulation. Before allowing cross-RP reliance on a decision, obtain a specific issuer/intermediary/legal-role assessment.

## 4. How to read ratings and timing

Each catalogue row has **V/I ratings from 1–5**:

- **5:** strongest candidate for discovery now.
- **4:** attractive conditional candidate.
- **3:** plausible, usually partner-led or later.
- **2:** defer; substantial dependencies or weak differentiation.
- **1:** no sensible direct entry under current assumptions.

These are comparative suitability judgments for this project, **not compliance scores**. A high rating never overrides a trust or legal gate. Issuer scores are lower when AskMI lacks independent authority or an accepting network.

Earliest conditional phases, measured from a funded start **T0**:

- **A — discovery now:** weeks 0–4; no production release implied.
- **B — first/adjacent pilot:** roughly months 2–6, only after foundation gates.
- **C — repeatable expansion:** roughly months 6–12.
- **D — specialist expansion:** month 12 onward, partner-funded and dependency-led.
- **W — watch/reject as current product:** no promised implementation date.

The phase orders evaluation and earliest delivery, not a guarantee that a country or issuer is ready. Ratings apply independently of country; every selected workflow needs a named country and actual issuer before scheduling.

## 5. Catalogue: 72 workflows

### 5.1 Travel, hospitality and mobility

Travel is a serious market to test. The Commission explicitly describes rental-related mDL use; IATA demonstrates adjacent digital-identity work, but IATA demonstrations do not establish EUDI-certified acceptance. [S02][S04][S05]

| ID  | Workflow and buyer                                          | V product / possible I product                                                                                    | V/I | Evidence               | Phase and decisive gate                                  |
| --- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --- | ---------------------- | -------------------------------------------------------- |
| T01 | Vehicle rental eligibility; rental operator/software vendor | Verify accepted licence, class and identity binding / rental-specific eligibility assertion, not a new licence    | 5/2 | D [S02]                | B: issuer supply, licence validity and rental acceptance |
| T02 | Hotel pre-arrival/check-in; hotel group/PMS vendor          | Request lawful registration attributes and match booking / hotel-issued stay entitlement, not government identity | 5/2 | D [S04]; H integration | B: national registration rules and PMS buyer             |
| T03 | Airline document pre-check; airline/check-in vendor         | Verify supported travel evidence before arrival / workflow receipt, not border admission                          | 3/1 | P [S05]                | D: carrier authority and accepted document profiles      |
| T04 | Border crossing/DTC; competent authority/integrator         | Contracted verification component / AskMI cannot replace sovereign travel-document issuer                         | 1/1 | D/P [S06][S05]         | W: sovereign programme and procurement                   |
| T05 | Lounge and loyalty access; lounge/loyalty platform          | Verify booking or membership entitlement / scoped access pass under operator authority                            | 4/3 | P [S05]                | C: entitlement issuer and anti-replay                    |
| T06 | Rail/ferry concession fares; ticket platform                | Combine accepted student/disability entitlement with fare policy / operator-issued ticket                         | 4/2 | H [S01]                | C: tariff acceptance and minimal disclosure              |
| T07 | Corporate travel booking; travel-management platform        | Check employee mandate, scope and spend limit / company-authorised booking permission                             | 3/2 | H [S07]                | C: mandate semantics and revocation                      |
| T08 | Fleet/vehicle-registration checks; fleet/rental platform    | Validate accepted registration and relevant role / fleet access entitlement, not registration title               | 3/1 | D/H [S01]              | D: registration source and ownership/use distinctions    |

### 5.2 Education, qualifications and professional learning

Europass provides an existing digital-learning credential ecosystem; European Student Card wallet work is described as a pilot. Existing digitally sealed learning records must not be assumed to be interchangeable with a particular EUDI presentation format. [S08][S09]

| ID  | Workflow and buyer                                          | V product / possible I product                                                                           | V/I | Evidence       | Phase and decisive gate                           |
| --- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | --- | -------------- | ------------------------------------------------- |
| E01 | Diploma checks for admission/hiring; university/ATS vendor  | Validate provenance and qualification fields / verification report with no invented awarding authority   | 5/2 | D [S08]        | B: supported format and institutional acceptance  |
| E02 | Training and microcredentials; training/LMS provider        | Verify completed course and issuer / AskMI-issued course evidence only if genuinely responsible          | 4/3 | D/P [S08][S07] | B: award authority and skill semantics            |
| E03 | Student-status eligibility; campus/discount platform        | Verify current status with minimum attributes / platform-specific discount entitlement                   | 5/2 | P [S09]        | B: current-status issuer and expiry               |
| E04 | Exam candidate identification; assessment provider          | Bind accepted identity to exam session / exam-result attestation only with assessment authority          | 4/2 | H [S08]        | C: accessibility, impersonation and exam policy   |
| E05 | Scholarship eligibility; university/foundation              | Combine independently verified eligibility evidence / funder's award decision, not invented income facts | 3/2 | H [S08]        | C: fairness, lawful basis and source availability |
| E06 | Professional licence/status; employer/regulator platform    | Check licence authority, scope and current status / no substitute professional licence                   | 4/1 | P [S10]        | C: live regulator source and country acceptance   |
| E07 | Continuing professional development; professional body      | Verify required learning evidence / course completion or body's renewal decision                         | 4/3 | H [S08]        | C: body-approved rules and auditability           |
| E08 | Cross-border qualification recognition; competent authority | Assemble authenticated evidence / authority-issued recognition, not automatic equivalence                | 3/1 | H [S10]        | D: recognition process and human decision owner   |

### 5.3 Work, contractors and physical access

The earlier contractor idea survives, but must compete against travel and education. A signed badge alone does not prove employment rights, professional competence or present authorisation.

| ID  | Workflow and buyer                                      | V product / possible I product                                                                  | V/I | Evidence     | Phase and decisive gate                            |
| --- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | --- | ------------ | -------------------------------------------------- |
| W01 | Contractor onboarding; facilities/construction platform | Verify selected training, employer and identity evidence / scoped onboarding-complete assertion | 4/3 | H [S08][S10] | B: buyer owns policy and accepts source issuers    |
| W02 | Site induction; site operator                           | Check completed induction and current access / site-specific induction credential               | 4/4 | H [S08]      | B: authoritative training record and expiry        |
| W03 | Posted-worker A1 checks; employer/compliance vendor     | Verify accepted social-security document / no AskMI substitute A1                               | 3/1 | P [S10]      | D: official document supply and legal workflow     |
| W04 | Right-to-work checks; employer/HR platform              | Route accepted evidence through national checking process / no self-issued work permission      | 2/1 | H [S01]      | D: country law and approved source                 |
| W05 | Association membership; association software vendor     | Verify membership/status / membership credential if association authorises actual issuer        | 4/3 | H [S27]      | B: sufficient customer pain versus existing login  |
| W06 | Visitor and temporary access; access-control vendor     | Verify invitation and identity proportionately / short-lived visitor pass                       | 4/3 | H [S04]      | C: physical access threat model and fallback       |
| W07 | Supplier technician access; industrial service platform | Combine employer role, training and time-bound work order / site/work-order permit              | 4/3 | H [S07]      | C: authorising operator and rapid revocation       |
| W08 | Employee-role lifecycle; IAM/HR platform                | Recheck role for sensitive workflow / employer-authorised role credential                       | 4/2 | H [S07]      | C: joiner/mover/leaver source and status freshness |

### 5.4 Business representation, procurement and trusted exchange

These opportunities are not missing from European work: WE BUILD identifies them explicitly. AskMI's opportunity is a specific integration or policy problem, not ownership of the category. European Business Wallet legislation was still represented by a Council negotiating position in the cited June 2026 source; do not treat that proposal as settled EUDI implementation law. [S07][S11]

| ID  | Workflow and buyer                                   | V product / possible I product                                                                                      | V/I | Evidence | Phase and decisive gate                          |
| --- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | --- | -------- | ------------------------------------------------ |
| B01 | Supplier KYB/onboarding; procurement vendor          | Check accepted company and representative evidence / limited due-diligence report, not authoritative registry facts | 4/2 | P [S07]  | C: registry access and residual diligence        |
| B02 | Acting for a company; enterprise SaaS vendor         | Verify identity plus mandate, scope and expiry / mandate only on principal's valid authority                        | 5/2 | P [S12]  | C: legal representation semantics                |
| B03 | Invoice origin/authority; ERP/e-invoice platform     | Verify submitting organisation and role / authorised submission receipt, not payment guarantee                      | 4/2 | P [S13]  | C: invoice-system integration and acceptance     |
| B04 | Foreign tax representation; tax software vendor      | Verify represented entity and permitted tax action / principal-authorised mandate                                   | 3/1 | P [S07]  | D: tax authority acceptance                      |
| B05 | Company/branch creation; registry service integrator | Evidence and representative verification / no substitute incorporation authority                                    | 2/1 | P [S07]  | D: registry process and procurement              |
| B06 | Business OOTS access; public-service integrator      | Authenticate authorised evidence request / no parallel unofficial evidence authority                                | 2/1 | P [S07]  | D: actual OOTS participation conditions          |
| B07 | Tender evidence reuse; procurement platform          | Check accepted certifications and company roles / tender-specific completeness statement                            | 3/2 | H [S07]  | C: contracting authority and evidence rules      |
| B08 | Data-space access; data-space operator               | Verify participant role and permitted resource use / membership/access attestation from accountable operator        | 4/3 | P [S14]  | C: ecosystem trust framework and policy contract |

### 5.5 Health, care and accessibility

Health-insurance entitlement, prescribing authority, treatment consent and access permission are different facts. A wallet presentation must not collapse them into a generic “health verified” response.

| ID  | Workflow and buyer                                 | V product / possible I product                                                                       | V/I | Evidence | Phase and decisive gate                                 |
| --- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | --- | -------- | ------------------------------------------------------- |
| H01 | ePrescription dispensing; pharmacy software vendor | Verify supported prescription and patient binding / no AskMI prescribing authority                   | 2/1 | D [S15]  | D: health-system integration and safety controls        |
| H02 | EHIC entitlement; provider/health insurer          | Verify accepted coverage evidence / no AskMI-issued EHIC                                             | 3/1 | P [S10]  | D: official source and national process                 |
| H03 | Clinician facility privileges; hospital IAM        | Check professional status plus hospital authorisation / hospital-authorised privilege credential     | 3/2 | H [S10]  | D: current privileges and patient-safety accountability |
| H04 | Patient-portal access; hospital portal vendor      | Identity-to-patient-record matching / local access entitlement, not clinical facts                   | 3/1 | H [S01]  | D: dangerous mismatches and recovery controls           |
| H05 | Research-data access; research institution         | Verify researcher role and approved project permit / ethics/data-controller-authorised permission    | 3/3 | H [S14]  | D: special-category data and project scope              |
| H06 | Caregiver representation; care platform            | Check valid, limited representation / no inference of legal guardianship from identity               | 2/1 | H [S12]  | D: authority, capacity and withdrawal                   |
| H07 | Disability concessions; venue/public service       | Verify entitlement without requesting diagnosis / service-specific concession, not disability status | 4/1 | D [S01]  | C: actual card availability and accessibility           |
| H08 | Disability parking; parking platform/authority     | Validate accepted permit and relevant use / no self-issued statutory parking entitlement             | 3/1 | D [S01]  | D: permit rules and enforcement authority               |

### 5.6 Finance, payments and insurance

Verification can support regulated workflows; it does not by itself satisfy every AML, SCA, credit or insurance obligation. Ratings intentionally favour integration partnerships over becoming a regulated financial operator.

| ID  | Workflow and buyer                                | V product / possible I product                                                                       | V/I | Evidence | Phase and decisive gate                            |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | --- | -------- | -------------------------------------------------- |
| F01 | Consumer bank onboarding; bank/KYC vendor         | Verify accepted identity evidence / narrow verification report, not “AML compliant” certificate      | 3/1 | D [S01]  | D: bank acceptance and full diligence process      |
| F02 | Corporate bank onboarding; bank platform          | Company plus authorised-representative checks / no bank or registry authority                        | 3/1 | P [S07]  | D: KYB integration and mandate validation          |
| F03 | Consumer payment authentication; PSP              | Integrate supported wallet authentication / not independent payment approval or money issuance       | 2/1 | D [S16]  | D: PSP-controlled SCA and transaction binding      |
| F04 | Corporate payment authorisation; bank/ERP vendor  | Validate mandate, limits and multi-person policy / principal-issued payment authority                | 3/1 | P [S07]  | D: bank acceptance and fraud controls              |
| F05 | Income evidence for lending; lender               | Verify accepted income evidence without unnecessary fields / no inferred creditworthiness credential | 3/1 | H [S27]  | D: income source, fairness and lending rules       |
| F06 | Insurance coverage proof; insurer/broker platform | Validate current coverage for a transaction / insurer-authorised coverage attestation                | 3/2 | H [S27]  | C: insurer participation and exclusions            |
| F07 | Claims evidence intake; claims platform           | Check evidence provenance and claimant role / intake receipt, not claim approval                     | 3/2 | H [S27]  | D: fraud workflow and retention duties             |
| F08 | Crypto-service onboarding; regulated provider     | Accepted identity component in wider onboarding / no substitute regulatory clearance                 | 2/1 | H [S01]  | D: applicable financial controls and buyer partner |

### 5.7 Consumer services, age, commerce and entitlements

Age verification is not excluded because public wallet tooling exists. The question is whether AskMI solves merchant integration, operation or minimisation better than existing options. A simple age-only verifier is unlikely to be a defensible standalone proposition without distribution.

| ID  | Workflow and buyer                                          | V product / possible I product                                                                          | V/I | Evidence       | Phase and decisive gate                               |
| --- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --- | -------------- | ----------------------------------------------------- |
| C01 | Restricted retail sales; retail/POS vendor                  | Verify accepted threshold proof / no re-issued official age fact                                        | 4/1 | D [S01]        | B: supported threshold proof and merchant integration |
| C02 | Online age-gated content; platform vendor                   | Minimal age eligibility check / no shared cross-site identity token                                     | 4/1 | D [S01]        | B: applicable age rules and anti-correlation          |
| C03 | Gambling eligibility; licensed operator                     | Age/identity component alongside exclusion checks / no all-purpose legal eligibility certificate        | 2/1 | H [S01]        | D: jurisdiction and wider gambling controls           |
| C04 | SIM registration; telecom onboarding vendor                 | Verify nationally accepted subscriber evidence / operator-authorised subscription fact only             | 3/2 | P [S17]        | C: operator partnership and national requirements     |
| C05 | Pseudonymous subscription login; content/community platform | Service-scoped login with eligibility where necessary / scoped membership, not global person identifier | 3/2 | D/X [S01][S18] | C: supported profile and recovery threat model        |
| C06 | Event tickets and passes; ticketing platform                | Verify admission entitlement and replay controls / promoter-authorised ticket                           | 4/3 | D [S01]        | B: distribution partner and anti-transfer policy      |
| C07 | Authorised parcel pickup; logistics platform                | Verify recipient or delegated pickup authority / carrier-authorised pickup pass                         | 4/3 | H [S27]        | C: delegation and redemption consistency              |
| C08 | Warranty/returns entitlement; retail-service platform       | Validate ownership/entitlement evidence as applicable / seller-authorised service eligibility           | 3/3 | H [S27]        | C: transfer, refund fraud and source records          |

### 5.8 Civic services, housing and cross-sector infrastructure

| ID  | Workflow and buyer                                                | V product / possible I product                                                                                   | V/I | Evidence     | Phase and decisive gate                             |
| --- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --- | ------------ | --------------------------------------------------- |
| X01 | Housing application evidence; property platform                   | Verify necessary applicant facts / no opaque tenant-worthiness credential                                        | 3/1 | H [S27]      | C: discrimination risk and proportionality          |
| X02 | Social-benefit application; public-service integrator             | Verify accepted eligibility evidence / authority, not AskMI, determines statutory benefit                        | 2/1 | H [S01]      | D: administrative rules and appeal process          |
| X03 | Library/resident membership; municipal vendor                     | Verify proportionate residence/status evidence / operator-authorised membership                                  | 4/3 | H [S01]      | B: procurement and value beyond existing cards      |
| X04 | Utility signup/address checks; utility platform                   | Accepted identity/address evidence / utility-issued account status                                               | 3/2 | H [S01]      | C: actual address source and fraud model            |
| X05 | Permit/licence applications; government integrator                | Evidence validation and workflow routing / no statutory issuing authority                                        | 2/1 | H [S01]      | D: competent authority and sector rules             |
| X06 | Qualified-signature workflow integration; SaaS vendor             | Route signing to appropriate qualified service and validate result / do not issue qualified signatures ourselves | 4/1 | D [S01]      | C: qualified partner and signature-validation scope |
| X07 | High-assurance account recovery; enterprise IAM                   | Rebind account through approved identity/recovery procedure / local recovery authorisation                       | 4/2 | H [S01]      | C: account-linking attacks and support fallback     |
| X08 | Digital Product Passport repair access; manufacturer/DPP platform | Verify repairer role and permitted data access / operator-authorised access entitlement                          | 3/3 | H [S19][S14] | C: DPP buyer and chosen access model                |

### 5.9 Emerging, composite and deliberately difficult cases

These are included to avoid hiding possibilities behind the initial shortlist. Inclusion does not mean endorsement.

| ID  | Workflow and buyer                                            | V product / possible I product                                                                                     | V/I | Evidence | Phase and decisive gate                                          |
| --- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --- | -------- | ---------------------------------------------------------------- |
| Z01 | Parent/guardian acting for a child; service provider          | Verify actual representation and scope / no guardianship inferred from shared name/address                         | 2/1 | H [S12]  | D: authoritative relationship and child safeguards               |
| Z02 | Supplier bank-detail changes; ERP/fraud platform              | Combine company representative and bank-account evidence / scoped change approval, not account ownership invention | 4/2 | H [S07]  | C: bank evidence and dual-control process                        |
| Z03 | Marketplace seller legitimacy; marketplace vendor             | Verify company/role evidence appropriate to seller / platform-specific seller status                               | 3/2 | H [S07]  | C: precise policy and no misleading guarantee                    |
| Z04 | Digital-estate representative access; estate/service platform | Check accepted death/representation evidence / no AskMI probate authority                                          | 1/1 | X        | W: legal authority, revocation and recovery complexity           |
| Z05 | Machine/IoT service authorisation; industrial IAM vendor      | Validate machine identity and human/org authorisation chain / operator-issued machine permission                   | 2/2 | X [S14]  | W: not automatically an EUDI natural-person wallet use           |
| Z06 | AI-agent delegated transactions; enterprise agent platform    | Enforce principal, action, limits and expiry / explicitly authorised delegation assertion                          | 2/2 | X [S20]  | W: unsettled profiles and liability; MCP alone insufficient      |
| Z07 | Public-warning authenticity; authority/app provider           | Validate authorised warning origin / only competent authority supplies authoritative warning                       | 2/1 | D [S01]  | D: broadcast-channel fit and authority participation             |
| Z08 | Remote public elections; election authority                   | Identity checks are only a small component / no generic “eligible voter” solution                                  | 1/1 | X        | W: secrecy, coercion resistance and election law unresolved here |

### Coverage boundary

This catalogue covers person identity, attributes, representation, entitlements, transactions, resource access and lifecycle management across public and private buyers. It includes online and proximity use, natural-person and organisation-linked workflows.

Further variations—sports-club membership, alumni privileges, apprenticeships, volunteer onboarding, equipment hire, coworking access, subscription benefits and transport staff access—map to the existing patterns rather than requiring eight new security stacks. Each can become a sales experiment under E02, W05, W06, T01, C05 or W07.

It does not classify unrestricted surveillance, cross-service identity monetisation, identity brokering without a lawful role, or invented sovereign credentials as acceptable opportunities. Humanitarian and other vulnerable-person deployments would require separate safeguarding, exclusion-risk and issuer-access research before being ranked.

## 6. Comparative shortlist: explicit, revisable scoring

To distinguish personal preference from evidence, the shortlist uses five 1–5 inputs:

- **E:** workflow evidence, 25%.
- **A:** plausible access to relevant credentials/issuer, 20%.
- **R:** reusable engineering fit, 25%.
- **S:** current sales access, 15%.
- **G:** manageable governance/operational complexity, 15%.

Total = 5E + 4A + 5R + 3S + 3G, out of 100. High G means easier to manage, not legally approved. Actual customer access is unknown, so **S=2 for every candidate**. Availability scores are hypotheses, not live compatibility measurements. This model ranks discovery attractiveness; it cannot establish profitability.

| Candidate                            | E   | A   | R   | S   | G   | /100 | Main downside                                   |
| ------------------------------------ | --- | --- | --- | --- | --- | ---- | ----------------------------------------------- |
| E03 Student status                   | 4   | 3   | 5   | 2   | 4   | 75   | Wallet pilot does not mean issuer availability  |
| E01 Learning-credential verification | 4   | 3   | 5   | 2   | 4   | 75   | Existing tooling and format fragmentation       |
| C01 Age-gated retail                 | 5   | 3   | 5   | 2   | 2   | 73   | Competition and country/merchant obligations    |
| T02 Hotel check-in                   | 4   | 3   | 5   | 2   | 3   | 72   | Country registration and PMS integration        |
| C06 Tickets/passes                   | 4   | 3   | 4   | 2   | 4   | 70   | Strong incumbents; wallet may add little value  |
| T01 Vehicle rental                   | 5   | 2   | 5   | 2   | 2   | 69   | Licence availability and operational liability  |
| B02 Company representation           | 4   | 2   | 5   | 2   | 2   | 65   | Mandate authority and revocation semantics      |
| W01 Contractor onboarding            | 3   | 2   | 5   | 2   | 3   | 63   | Multiple fragmented authoritative sources       |
| W02 Site induction                   | 2   | 4   | 4   | 2   | 3   | 61   | Easy existing substitutes; weak demand evidence |
| B08 Data-space access                | 4   | 2   | 4   | 2   | 2   | 60   | Ecosystem-specific trust contracts              |

Why investigate rental despite a lower score? It has an explicitly documented operational workflow and potentially differentiated multi-credential policy integration. The scoring penalises its supply and liability uncertainty; discovery can resolve those uncertainties. A simpler pilot can ship first without abandoning travel.

**Sensitivity:** improving issuer access from 2 to 4 adds eight points; moving sales access from 2 to 5 adds nine. A real committed buyer can reverse this ordering. Scores within five points should be treated as ties rather than spurious precision.

Issuer direction: W02 is the clearest early experiment only if AskMI actually operates/controls the relevant training assertion and recipients accept it. More commonly, sell issuance tools to the site or training provider so that it remains the accountable issuer. For mandates, licences, prescriptions and state entitlements, partnering with the authoritative issuer is preferable to claiming its role.

## 7. Six concrete product experiments

These are proposed products, not verified customer requirements.

### Experiment 1: rental eligibility adapter — T01

- Buyer/channel: rental fleet operator or rental-management software vendor.
- Trigger: reservation or pickup requires identity and licence checks.
- Minimum result: accepted issuer, valid presentation, relevant class/status and transaction binding; request additional facts only when needed.
- V version: integrate accepted evidence into the operator's decision. I version: a separate rental eligibility statement only with explicit acceptance and responsibility; never reissue the licence.
- MVP: one operator, country, credential profile and reservation integration; supervised exception handling.
- Exclude: autonomous damage/fraud scoring, border checks, universal offline operation.
- Measure: manual-review rate, pickup handling time, rejected invalid evidence, fallback completion and unnecessary fields avoided.
- Stop if: no accepted licence source, no integration owner or no operational improvement over existing checks.

### Experiment 2: hotel registration minimisation — T02

- Buyer/channel: PMS vendor or hotel group, rather than individual traveller acquisition.
- Trigger: pre-arrival registration followed by booking/person matching.
- V version: country/property-specific lawful-field policy and verified-data handoff. I version: hotel-authorised stay/access entitlement, not a recycled identity credential.
- MVP: one property group, one country and one PMS integration, with staff fallback.
- Exclude: treating every country as having identical guest-registration duties or retaining whole credentials by default.
- Measure: check-in time, correction rate, support cases and data collected per check-in.
- Stop if: legal requirements remove the proposed benefit or the PMS already supplies an equivalent economical integration.

### Experiment 3: learning-to-eligibility bridge — E01/E03

- Buyer/channel: university, student-service platform or recruitment/LMS vendor.
- Trigger: institution must verify qualification or current student status.
- V version: source-aware verification mapped to a narrow eligibility rule. I version: platform-specific entitlement or genuinely awarded learning assertion; awarding institution remains authoritative.
- MVP: one institution, one credential type and one receiving workflow.
- Exclude: equating diploma possession with current enrolment, or verified qualification with automatic professional recognition.
- Measure: verification turnaround, issuer coverage, expiry/status failures and manual cases.
- Stop if: source format is unavailable, existing Europass/native tooling solves the buyer's problem, or no one pays for integration. [S08]

### Experiment 4: contractor-to-work-order access — W01/W07

- Buyer/channel: facilities or industrial-service software vendor.
- Trigger: a technician needs access for a particular job and time.
- V version: combine employer role, relevant training and operator-issued work order; keep source provenance separate.
- I version: operator-authorised short-lived site permission, not a professional licence.
- MVP: one site, training source and work-order system; revocation and denied-access escalation.
- Measure: access delay, stale authorisations blocked and reviewer effort.
- Stop if: buyer cannot define who authorises access or requires unsafe offline acceptance.

### Experiment 5: mandate-controlled sensitive changes — B02/Z02

- Buyer/channel: ERP/procurement platform.
- Trigger: supplier bank details or an organisationally sensitive record changes.
- V version: verify company representation, action scope and independent account evidence; apply dual control.
- I version: principal-authorised mandate or action receipt under a separately assessed role.
- MVP: one action, organisation source and revocable mandate model; no payment execution.
- Measure: manual approvals, unauthorised change attempts rejected and correct escalation.
- Stop if: no trustworthy account evidence, unclear mandate semantics or buyer expects identity alone to guarantee absence of fraud.

### Experiment 6: role-gated repair/data access — B08/X08

- Buyer/channel: data-space operator, manufacturer or repair-platform vendor.
- Trigger: a repairer/researcher needs a specific protected dataset.
- V version: verify accepted membership/role and project/resource permission; deny excess scope.
- I version: operator-authorised membership/access credential, not a generic certificate of trustworthiness.
- MVP: one ecosystem, resource class and authorising organisation.
- Measure: onboarding effort, revoked access blocked and policy integration reuse.
- Stop if: ordinary federated IAM meets the requirement more cheaply or no portable credential demand exists.
- Evidence boundary: DPP access-control integration is our hypothesis, not a claimed legal requirement to use EUDI. [S19]

## 8. Go-to-market strategy and alternatives

### Recommended route: vertical software distribution

1. Sell a paid workflow-discovery and integration package to a vertical vendor or operational buyer.
2. Deliver an RP-controlled verifier/policy adapter with explicit issuer/profile coverage.
3. Charge for integration, supported deployments and operational service; validate pricing with actual procurement, not invented market benchmarks.
4. Expand to adjacent workflows through the same buyer channel.
5. Consider institution-operated issuance tooling before AskMI-operated attestation services.

A generic “REST API for wallets” is not sufficient differentiation. Signicat, Procivis and walt.id already describe wallet/verification/issuance tooling. This is evidence of competition and potential partnership, not an independent feature, pricing or certification benchmark. [S21][S22][S23]

| Route                              | Advantage                                      | Cost/risk                                                  | Recommendation                           |
| ---------------------------------- | ---------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------- |
| Direct vertical pilot              | Fast understanding of real workflow            | Bespoke integration and single-customer dependence         | First learning route                     |
| Vertical software partner          | Existing distribution and repeated deployments | Partner dependency and longer negotiations                 | Preferred scaling route                  |
| General verifier API               | Broad addressable integrations                 | Crowded market and weak differentiation                    | Component, not initial positioning       |
| Issuance tooling for institutions  | Institution retains source authority           | Issuer onboarding/support burden                           | Conditional adjacent product             |
| AskMI-operated attestation network | Potential recurring cross-party utility        | Authority, liability, lifecycle and network cold start     | Defer until demand/acceptance proven     |
| Certified wallet product           | Direct wallet control                          | Separate certification, custody and distribution challenge | Not justified by current evidence        |
| Qualified trust-service operation  | Specific regulated service proposition         | Qualification and sustained operational obligations        | Only with a funded business case/partner |

Potential outreach channel: the Commission's RP Engagement Programme, alongside relevant pilot consortia and vertical vendors. Participation is not certification, funding or a customer commitment. [S28]

### Discovery protocol: first four weeks

For each of rental, hotel and learning/student tracks, target three buyer interviews and two issuer/integration interviews. These are proposed activities, not completed research.

Ask for the actual workflow, current cost, failure cases, system owner, available credentials, acceptable issuers, deployment constraints, procurement path and paid-pilot criteria. Obtain consent before receiving any personal or confidential evidence.

Select a first build only when:

- A named buyer owns the operational problem and agrees measurable success criteria.
- An actual issuer/wallet/profile is accessible for the intended jurisdiction.
- The RP and any intermediary/issuer roles are identified.
- No unresolved high-risk trust finding affects the selected path.
- The customer has a funded pilot route, not merely enthusiasm.
- There is a lawful fallback for users unable or unwilling to use the wallet.

Country selection is deliberately not invented. Germany and Austria are possible discovery locations because they were discussed, not verified launch recommendations. Compare buyer access, actual credential supply, local obligations and procurement before choosing.

## 9. Architecture that supports breadth without laundering trust

Build shared capabilities, not 72 independent implementations:

1. **Protocol adapter:** explicitly supported version/format combinations; reject unsupported or downgraded profiles.
2. **Verification core:** signatures, trusted issuer authorisation, holder/session binding, freshness, status and all requested constraints.
3. **Provenance-aware facts:** distinguish issuer-signed attributes, holder statements, verified presentation results and local policy inferences.
4. **Policy module:** purpose-specific minimum claims and versioned business rules; unknown means deny or controlled manual review, never silently valid.
5. **User handoff:** maintain the wallet's required approval and requesting-party visibility.
6. **Business adapter:** PMS, rental booking, LMS, IAM or ERP integration.
7. **Operational layer:** bounded evidence, retention schedule, incident handling, status outages and accessible fallback.
8. **Optional separate issuance service:** own keys, authority, schema, status, liability and recipient acceptance; never enabled merely because the verifier can sign JSON.

The verification result must be scoped to the requesting RP and transaction. Do not present a local Boolean as an issuer-authenticated predicate or a transferable qualified attestation. Standard selective disclosure can preserve supported proofs; arbitrary rewriting cannot.

“Edge” must name a deployment boundary. Initial preference is the RP's controlled backend or site appliance, without moving holder keys from the wallet. Browser-only validation, offline proximity and remote central processing have different attack and availability models.

Offline acceptance is not a free feature: establish what freshness/status evidence is available, how stale it may become, what the scheme allows and which risks the RP accepts. Where a required trust check cannot be satisfied, deny or use an approved fallback.

Do not promise “zero retention” universally. Minimise personal data, but assess necessary evidence and legal retention; non-qualified trust-service operational rules can themselves require records. [S25]

## 10. Step-by-step implementation order

### Planning assumptions

Illustrative capacity: two engineers plus part-time domain/legal/security support, with two-week increments. No user-confirmed budget or capacity exists. Windows below are planning hypotheses, not delivery or certification guarantees. Discovery can run alongside foundation work; production feature delivery remains sequential.

| Step | Window from T0              | Deliverable                                                          | Exit gate / stop rule                                                        |
| ---- | --------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 0    | Weeks 0–2                   | Role map, source/profile register, three-track interview plan        | Named decision owner; no assumption that AskMI is certified                  |
| 1    | Weeks 0–6, extend if needed | Repair verification/session/trust blockers from desk audit           | Adversarial tests fail closed; independent review of chosen path             |
| 2    | Weeks 2–6                   | Actual wallet/issuer/RP integration spike                            | Real supported presentation validates; no mock-only readiness claim          |
| 3    | Weeks 4–8                   | One selected vertical's lawful-data policy and adapter specification | Buyer, country, source availability and paid-pilot criteria confirmed        |
| 4    | Months 2–3, conditional     | First supervised pilot: highest gate-passing B candidate             | Measured benefit and safe fallback; no critical trust defect                 |
| 5    | Months 3–4                  | Pilot hardening, support, lifecycle and evidence package             | Operational acceptance and documented residual risks                         |
| 6    | Months 4–6                  | Second workflow using same core and preferably same channel          | Demonstrated reuse; no new issuer role smuggled into adapter                 |
| 7    | Months 6–9                  | Third workflow in a second sector                                    | Core works without copying business-specific trust assumptions               |
| 8    | Months 6–12                 | Mandates or data-space access, if partner-funded                     | Authoritative scope/status semantics and ecosystem acceptance                |
| 9    | Month 12+                   | Specialist health/finance/public-sector integrations                 | Domain owner, legal review, required assurance and procurement               |
| 10   | Separate funded decision    | Institution issuance tooling or AskMI issuer operation               | Authority, acceptance network, applicable obligations and lifecycle verified |

Step 1 must address the findings already recorded in the audit, not rely on passing happy-path tests:

- Make cryptographic verification mandatory for accepted results.
- Enforce required holder binding, nonce/audience/session checks and requested constraints.
- Generate expected request state independently of the received response.
- Authenticate trust data and enforce validity/freshness; remove permissive trust fallbacks.
- Preserve required wallet approval; do not equate local ALLOW with permission to auto-present.
- Keep holder keys within the appropriate wallet security boundary.
- Pin supported profiles and distinguish computed predicates from issuer-authenticated proofs.

Relevant existing areas include `src/packages/oid4vp-verifier`, `src/packages/shared-crypto`, `src/packages/policy-engine`, `src/packages/predicates` and wallet/demo integration. The audit's findings are baseline observations, not proof of fixes in this documentation task.

### Explicit queue covering all 72 IDs

This is an **evaluation queue within phase**, not authorisation to build every entry. Failed gates move an item back, even if another lower-ranked item proceeds.

- **B:** E03 → E01 → T02 → T01 → C01 → C02 → W01 → W02 → C06 → W05 → X03 → E02.
- **C:** B02 → B08 → W07 → E06 → T05 → T06 → W08 → X06 → Z02 → C07 → E07 → B01 → B03 → X07 → T07 → E04 → H07 → F06 → C04 → X08 → B07 → C08 → X04 → C05 → W06 → E05 → X01 → Z03.
- **D:** T03 → W03 → H02 → F01 → F02 → H03 → F04 → H05 → T08 → H08 → B04 → E08 → F03 → H01 → W04 → F05 → F07 → H04 → H06 → Z01 → C03 → F08 → B05 → B06 → X02 → X05 → Z07.
- **W:** Z06 → Z05 → Z04 → T04 → Z08; research only until a materially different funded/authorised opportunity exists.

### Conditional first-three delivery paths

- **If a rental partner and accepted mDL source exist:** T01 → T02 or T05 through a reachable travel partner → T07 after mandate capability.
- **If a learning issuer is accessible first:** E03 or E01 → E02/E07 → W01 with an actual employer/site partner.
- **If a hotel group commits first:** T02 → T05/C06 where the same channel has demand → T01 only when licence supply is real.
- **If only controlled site credentials are available:** W02 → W01 → W07; explicitly a controlled ecosystem pilot, not evidence of broad EUDI interoperability.

Do not force these paths if the second buyer is absent. Revalidate commercial demand at every step.

## 11. Acceptance and stop conditions

Before any live pilot:

- Role-specific legal review and country/workflow obligations are recorded.
- Original issuer authority, schema meaning, signature chain and applicable status checks are verified.
- Mandatory holder/session binding and anti-replay checks pass negative tests.
- User-facing requesting party and data request remain accurate.
- Minimal disclosure is technically supported; no invented selective-disclosure capability.
- Revocation, expiry, offline and outage behaviour are agreed and tested.
- Accessibility, non-wallet alternatives and complaint/correction routes are defined.
- Retention, deletion, incident response and processor/controller responsibilities are documented.
- No unsupported “EU certified,” “qualified,” “LoA high,” “anonymous” or “zero knowledge” marketing claim appears.
- A customer measures improvement against its existing workflow.

Commercial stop conditions: no accepted credential source; no accountable buyer; ordinary IAM/API checks solve the problem economically; a new trusted issuer would be needed without authority or acceptance; or the only value proposition is collecting more identity data.

Review quarterly. Update evidence dates, profile availability, buyer access and scores. Promote entries only with evidence; retire weak ideas rather than maintain a perpetual feature backlog.

## 12. Source register

Sources establish only the facts stated beside their references. The catalogue's proposed products, scores, commercial assumptions and timeline are this report's analysis.

- **S01 — Commission use-case manuals:** [Use-case index](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/896827987/Use+case+manuals). Official workflow inventory; uneven publication status, not universal deployment.
- **S02 — Commission mobile driving licence manual:** [mDL manual](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/929202846/The+Mobile+Driving+License+manual). Rental workflow; some legislative timing text is stale.
- **S03 — Driving-licence legislation:** [Directive (EU) 2025/2205](https://eur-lex.europa.eu/eli/dir/2025/2205/oj/eng). Legal text, not evidence that a particular rental-compatible credential is available.
- **S04 — Commission proximity identification:** [Proximity scenarios](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/930451396/Identification+in+proximity+scenarios). Official workflow examples.
- **S05 — IATA industry activity:** [One ID](https://www.iata.org/en/programs/passenger/one-id/), [digital identity](https://www.iata.org/en/programs/innovation/digital-identity/), [April 2026 proof-of-concept release](https://www.iata.org/en/pressroom/2026-releases/2026-04-08-01/). Industry demonstrations; not EUDI certification.
- **S06 — Commission travel credentials:** [Travel manual](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/930451772/Travel+Credentials). Travel-document workflow reference.
- **S07 — WE BUILD:** [Project use cases](https://www.webuildconsortium.eu/). Business-wallet pilot agenda; not a legal mandate or customer commitment.
- **S08 — Europass:** [European Digital Credentials for Learning](https://europass.europa.eu/en/european-digital-credentials-learning). Existing learning-credential ecosystem; profile compatibility must be checked.
- **S09 — European Student Card:** [Verifiable-credential pilot](https://erasmus-plus.ec.europa.eu/european-student-card-initiative/news/piloting-a-digital-european-student-card-as-a-verifiable-credential). Pilot status, not universal availability.
- **S10 — Social security and qualifications:** [ESSPASS](https://employment-social-affairs.ec.europa.eu/policies-and-activities/moving-working-europe/eu-social-security-coordination/digitalisation-social-security-coordination/european-social-security-pass_en), [DC4EU](https://www.dc4eu.eu/). A1/EHIC and education/professional pilot context.
- **S11 — Business Wallet legislative posture:** [Council negotiating position, 9 June 2026](https://www.consilium.europa.eu/en/press/press-releases/2026/06/09/european-business-wallets-council-adopts-negotiating-position/). Do not equate a negotiating position with adopted final law.
- **S12 — Representation:** [WE BUILD company representative use case](https://www.webuildconsortium.eu/use-cases/company-representative-acting-on-behalf-of-a-company). Company mandates; personal guardianship extensions are our hypotheses.
- **S13 — eInvoicing:** [WE BUILD use case](https://www.webuildconsortium.eu/use-cases/einvoicing). Pilot workflow.
- **S14 — Data spaces:** [WE BUILD trusted data sharing](https://www.webuildconsortium.eu/use-cases/trusted-data-sharing-for-data-spaces). Ecosystem access use case.
- **S15 — Prescriptions:** [Commission ePrescription manual](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/930452930/ePrescription). Domain workflow, not AskMI prescribing authority.
- **S16 — Payments:** [Commission payment authentication manual](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/935397429/Payment+Authentication). Authentication workflow, not complete financial compliance.
- **S17 — Pilot origins:** [Commission four-project announcement](https://digital-strategy.ec.europa.eu/en/news/eu-digital-identity-4-projects-launched-test-eudi-wallet). Historical 2023 scope, including SIM; not current production status.
- **S18 — Technical pseudonym discussion:** [ARF discussion](https://eudi.dev/latest/discussion-topics/e-pseudonyms-including-user-authentication-mechanism/). Technical discussion, not binding law; latest URL is mutable.
- **S19 — Product passports:** [Commission Digital Product Passport](https://single-market-economy.ec.europa.eu/single-market/digital-product-passport_en). Background for our proposed role-based access integration.
- **S20 — Agent identity exploration:** [WE BUILD AI-agent non-paper](https://www.webuildconsortium.eu/trusted-identities-for-ai-agents-an-opportunity-for-europe). Exploratory proposal, not a settled delegation profile.
- **S21 — Commercial alternative:** [Signicat EUDI Wallet offering](https://www.signicat.com/use-cases/eudi-wallet). Vendor claims; no independent benchmark.
- **S22 — Commercial alternative:** [Procivis eIDAS documentation](https://docs.procivis.ch/eidas). Vendor implementation documentation.
- **S23 — Open tooling alternative:** [walt.id community-stack quickstart](https://docs.walt.id/community-stack/home/quickstart-5-min). Tooling availability, not certification.
- **S24 — eIDAS/EUDI legal framework:** [Consolidated Regulation 910/2014, 20 May 2024 text](https://eur-lex.europa.eu/eli/reg/2014/910/2024-05-20/eng), [amending Regulation 2024/1183](https://eur-lex.europa.eu/eli/reg/2024/1183/oj/eng). Role distinctions and wallet/RP/trust-service provisions; refresh all applicable implementing acts for a selected deployment.
- **S25 — Non-qualified trust-service operations:** [Implementing Regulation (EU) 2025/2160](https://eur-lex.europa.eu/eli/reg_impl/2025/2160/oj/eng). Risk-management and operational requirements.
- **S26 — Data protection:** [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng). Lawful basis, minimisation and applicable individual safeguards; selected workflows require specific assessment.
- **S27 — General credential patterns:** [W3C Verifiable Credentials Use Cases](https://www.w3.org/TR/vc-use-cases/). Standards-group examples, not proof of EUDI compatibility or demand.
- **S28 — Integration outreach:** [Commission RP Engagement Programme](https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/978681884/Relying+Party+Engagement+Programme). Potential engagement channel.

## 13. Immediate decision requested after reading

Approve a **four-week discovery and trust-foundation planning stage**, not 72 feature commitments. Supply available buyer contacts, team capacity and candidate countries. Then choose one gate-passing pilot with documented source credentials and a paid operational problem.

The strategic correction is straightforward: **keep the opportunity map broad, the trust boundary strict, and each implementation narrow enough to prove.**
