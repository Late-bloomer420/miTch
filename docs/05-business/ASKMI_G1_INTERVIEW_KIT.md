# AskMI G1 discovery interview kit

**Status:** Interview baseline for G1  
**Gate date:** 11 October 2026  
**Gate targets:** 20 completed interviews; at least 8 problem confirmations; at least 3 interviews that identify a budget owner, procurement trigger, or deadline  
**Roadmap:** [#142](https://github.com/Late-bloomer420/miTch/issues/142)  
**GTM tracker:** [#143](https://github.com/Late-bloomer420/miTch/issues/143)

> This kit tests a market hypothesis. It does not claim certification, compliance, production readiness, customers, revenue, or European Commission endorsement.

## 1. Hypothesis under test

AskMI may create value as an independent EUDI request-governance and evidence layer for relying parties and integrators. The first workflow is purpose-bound, data-minimised hotel pre-arrival/check-in in DACH.

The interview must test whether an organisation has a concrete problem in deciding, approving, changing, and proving:

1. which business purpose justifies a wallet request;
2. which minimum claims are permitted for that purpose;
3. which policy, trust source, registration scope, and software revision produced a decision;
4. what happens when a rulebook, credential schema, wallet, or connector changes; and
5. whether review evidence can be retained without retaining complete credential payloads.

Do not lead with a wallet product, zero-knowledge claims, a feature tour, or a sales pitch. Ask about the interviewee's current workflow before describing AskMI.

## 2. Evidence and privacy rules

- Keep names, contact details, company-confidential notes, recordings, and contracts outside the public repository.
- Assign each interview an anonymised ID such as `G1-HOSP-01`, `G1-INT-01`, or `G1-ID-01`.
- Store only aggregate counts and approved anonymised findings in GitHub.
- Obtain permission before recording. A completed interview does not require a recording.
- Record what the interviewee said. Mark interviewer inference separately.
- Count one completed interview once. Multiple signals from one interview still count as one buyer/procurement-signal interview.
- Report the number of unique organisations separately.

## 3. Who to interview

Use the S01 cohort as the minimum mix:

| Cohort | Target roles | Planned count |
|---|---|---:|
| Hospitality/service operator | Hotel operations, digital guest journey, IT, privacy, security, procurement | 4+ |
| Integrator/service platform | CTO, identity/IAM lead, solution architect, delivery lead | 3+ |
| Identity/privacy/security owner | EUDI product owner, IAM lead, privacy engineering, security architecture | 3+ |
| Second cohort | Fill evidence gaps while preserving role diversity | 10 |

Avoid filling the sample with people who share the same organisation, role, or relationship to the project.

## 4. Standard introduction

### German

> Danke, dass Sie sich Zeit nehmen. Ich untersuche, wie Unternehmen digitale Identitätsnachweise und EUDI-Wallet-Anfragen vorbereiten, freigeben und nachweisen. Mich interessieren Ihre heutigen Abläufe, Probleme und Entscheidungen.  
>   
> Das ist ein Forschungsinterview, keine Produktdemo. Ich werde keine vertraulichen Kunden-, Mitarbeiter- oder Gästedaten in einem öffentlichen Repository speichern. Darf ich anonymisierte Erkenntnisse und aggregierte Zählwerte verwenden?  
>   
> Optional: Darf ich das Gespräch nur für meine privaten Notizen aufzeichnen? Ein Nein ist völlig in Ordnung.

### English

> Thank you for making the time. I am researching how organisations prepare, approve, and evidence digital-identity and EUDI wallet requests. I want to understand your current workflow, problems, and decisions.  
>   
> This is a research interview, not a product demo. I will not place confidential customer, employee, or guest information in a public repository. May I use anonymised findings and aggregate counts?  
>   
> Optional: May I record this conversation only for my private notes? Saying no is completely fine.

## 5. Core 30-minute interview

Ask these questions in order. Use the prompts only when the answer needs clarification.

### A. Role and real workflow — 5 minutes

1. **What is your role in digital identity, guest/customer onboarding, privacy, security, or procurement?**
   - Which decisions do you personally make?
   - Who else must approve them?

2. **Tell me about the most recent real workflow where your organisation requested, checked, or planned to use identity information.**
   - What triggered it?
   - Which user journey was involved?
   - Which systems and teams participated?

3. **What information or claims did you request, and how did you decide what was necessary?**
   - Was the business purpose written down?
   - Who challenged excessive data?

### B. Problem and consequence — 8 minutes

4. **Where does that workflow become slow, uncertain, risky, or difficult to prove?**
   - Ask for a concrete incident or decision.
   - Do not count general concern without an example.

5. **What happens when a rule, wallet, credential schema, connector, or internal requirement changes?**
   - How do you detect the change?
   - Who decides whether the request remains acceptable?
   - How do you test the decision?

6. **If the current process fails, what is the consequence?**
   - Delay, manual work, legal/privacy review, security risk, lost conversion, failed audit, blocked launch, or another measurable effect?
   - How often does this occur?

7. **How serious is this compared with your other priorities? Why?**
   - What makes it urgent now?
   - What would make it remain unsolved?

### C. Current solution and alternatives — 5 minutes

8. **How do you handle this today?**
   - Internal policy/configuration, spreadsheets, tickets, legal review, verifier tooling, integrator, or manual checks?
   - Who maintains it?

9. **What works well in the current approach, and what is missing?**

10. **Have you tried or considered another solution?**
    - Build internally?
    - Use official/open-source verifier components?
    - Buy from an IAM or integration provider?
    - Accept the current risk?

### D. Buyer, procurement, timing, and price — 7 minutes

11. **Who owns the business outcome and who controls the budget for solving this?**
    - Capture a role or function. Do not publish a person's name.

12. **What event would start procurement or approve an external engagement?**
    - Regulation, customer demand, audit finding, launch milestone, incident, integration project, or budget cycle?

13. **Is there a date by which the organisation must make progress or a decision? What drives that date?**

14. **How would a four-to-six-week readiness engagement be bought?**
    - Expected approvers, vendor requirements, security/privacy review, purchasing route, and typical lead time?

15. **For one bounded journey, what would make a €12,000–€25,000 readiness engagement credible or impossible?**
    - For an early design partner, test the €7,500–€12,000 range only in exchange for agreed evidence or case-study value.
    - Ask for reasoning; do not negotiate during discovery.

### E. Outcome and referral — 5 minutes

16. **What deliverable would help your organisation make a real decision?**
    - Purpose/claim map, policy configuration, test flow, evidence pack, gap register, pilot conditions, or another result?

17. **How would you measure success after four to six weeks?**

18. **Who has a different view of this problem and should be interviewed next?**

19. **What should I have asked but did not?**

## 6. Role-specific modules

Use one module after question 10. Do not ask every module in the same interview.

### A. Hospitality or service operator

#### German

1. Bitte führen Sie mich durch den heutigen Ablauf von Buchung oder Voranreise bis Check-in.
2. Welche Identitäts- oder Berechtigungsdaten werden an welchem Schritt benötigt?
3. Welche Daten werden aus rechtlichen Gründen benötigt und welche aus betrieblichen Gründen?
4. Wo entstehen manuelle Prüfungen, Wartezeiten, Abbrüche oder wiederholte Dateneingaben?
5. Welche Unterschiede zwischen Hotelgruppe, einzelner Unterkunft, PMS, Buchungsplattform und Behörden erschweren den Ablauf?
6. Wer müsste einer Wallet-basierten Änderung zustimmen?
7. Welcher einzelne Check-in-Anwendungsfall wäre klein genug für einen Test?

#### English

1. Walk me through the current journey from booking or pre-arrival to check-in.
2. Which identity or entitlement data is needed at each step?
3. Which data is required for legal reasons and which for operational reasons?
4. Where do manual checks, delays, abandonment, or repeated data entry occur?
5. Which differences between hotel group, property, PMS, booking platform, and authorities make the workflow difficult?
6. Who would need to approve a wallet-based change?
7. Which single check-in use case would be small enough to test?

### B. Integrator or service platform

#### German

1. Wie übersetzen Sie heute Kundenanforderungen in Wallet-Anfragen, Claims und Vertrauensregeln?
2. Welche Teile sind je Kunde oder Land unterschiedlich?
3. Wie vermeiden Sie, dass Connector- oder Schemaänderungen unbemerkt die Anfrage verändern?
4. Welche Nachweise verlangen Kunden vor Abnahme oder Produktivsetzung?
5. Welche Arbeit würden Sie selbst behalten und welche externe Governance- oder Evidence-Komponente wäre sinnvoll?
6. Wodurch würde eine neue Komponente Integrationskosten senken oder erhöhen?
7. Welche Support- und Haftungsfragen blockieren eine Beschaffung?

#### English

1. How do you translate customer requirements into wallet requests, claims, and trust rules today?
2. Which parts vary by customer or country?
3. How do you prevent connector or schema changes from silently changing a request?
4. What evidence do customers require before acceptance or production use?
5. Which work would you retain, and where could an external governance or evidence component help?
6. What would make a new component reduce or increase integration cost?
7. Which support and liability questions would block procurement?

### C. Identity, privacy, security, or EUDI owner

#### German

1. Wie werden Zweck, Datenminimierung, Vertrauensquelle und Registrierung heute freigegeben?
2. Welche Artefakte benötigen Datenschutz, Sicherheit, Revision und Produktverantwortliche?
3. Wie wird eine Entscheidung an die konkrete Policy- und Softwareversion gebunden?
4. Was muss bei Änderungen erneut geprüft werden?
5. Welche Daten dürfen in einem Evidence Record auf keinen Fall enthalten sein?
6. Welche Fehler müssen standardmäßig zu einer Ablehnung führen?
7. Welche Aussage dürfte ein Anbieter ohne unabhängige Prüfung keinesfalls machen?

#### English

1. How are purpose, data minimisation, trust source, and registration approved today?
2. Which artifacts do privacy, security, audit, and product owners require?
3. How is a decision tied to the exact policy and software revision?
4. What must be reviewed again after a change?
5. Which data must never appear in an evidence record?
6. Which failures must result in denial by default?
7. Which claim must a supplier avoid without independent assessment?

## 7. Short 15-minute version

Use this only when 30 minutes is unavailable. It can count as a completed interview if every required evidence field receives a clear answer.

### German

1. Erzählen Sie mir vom letzten konkreten Identitäts- oder Wallet-Workflow, an dem Sie gearbeitet haben.
2. Wo entstand ein echtes Problem, und welche Folge hatte es?
3. Wie lösen Sie das heute, und was fehlt?
4. Wer verantwortet das Ergebnis und das Budget?
5. Welches Ereignis oder welcher Termin würde eine Beschaffung auslösen?
6. Was müsste eine vier- bis sechswöchige Readiness-Leistung liefern, damit sie kaufbar wäre?
7. Wer sollte dazu noch befragt werden?

### English

1. Tell me about the last concrete identity or wallet workflow you worked on.
2. Where did a real problem occur, and what was the consequence?
3. How do you solve it today, and what is missing?
4. Who owns the outcome and the budget?
5. Which event or deadline would trigger procurement?
6. What would a four-to-six-week readiness engagement need to deliver to be purchasable?
7. Who else should be interviewed?

## 8. Neutral concept test

Use only after the current workflow, problem, alternatives, buyer, and timing have been discussed.

### German

> Ich teste folgende Arbeitshypothese: Eine unabhängige Schicht prüft Wallet-Anfragen gegen freigegebene Zwecke und minimale Claims und erzeugt einen datensparsamen Nachweis über Policy, Trust-Entscheidung, Ergebnis und Softwareversion. Für einen klar abgegrenzten Anwendungsfall würde eine Readiness-Leistung den Datenfluss abbilden, notwendige und übermäßige Claims identifizieren, eine Policy und einen Testablauf konfigurieren und ein Evidence Pack mit Gap-Register und Pilotbedingungen liefern.  
>   
> Welcher Teil wäre für Ihre Organisation nützlich, welcher unnötig und welcher unklar?

Follow with:

1. What would you use instead?
2. What evidence would you need before trusting the result?
3. What would stop you from buying or testing it?
4. Who would have to approve the next conversation?

### English

> I am testing this working hypothesis: an independent layer evaluates wallet requests against approved purposes and minimum claims and produces a data-minimised record of the policy, trust decision, outcome, and software revision. For one bounded use case, a readiness engagement would map the data flow, identify necessary and excessive claims, configure a policy and test flow, and deliver an evidence pack with a gap register and pilot conditions.  
>   
> Which part would be useful to your organisation, which part unnecessary, and which part unclear?

Use the same four follow-up questions above.

## 9. Interview scorecard

Complete this immediately after the interview.

| Field | Entry |
|---|---|
| Interview ID | |
| Date | |
| Cohort | Hospitality / Integrator / Identity-Privacy-Security / Other |
| Participant role | |
| Organisation type | |
| Country/market | |
| Concrete workflow | |
| Current solution | |
| Problem described | |
| Consequence | |
| Frequency/severity | |
| Problem confirmation | Yes / No / Unclear |
| Confirmation rationale | |
| Economic buyer role | |
| Technical champion role | |
| Budget owner identified | Yes / No |
| Procurement trigger identified | Yes / No |
| Deadline identified | Yes / No |
| Qualifying buyer signal | Yes / No |
| Procurement path | |
| Readiness Sprint price reaction | Credible / Too high / Too low / No budget / Unclear |
| Required deliverable | |
| Success measure | |
| Alternatives | |
| Objections | |
| Referral role | |
| Private evidence reference | |
| Interviewer inference | |
| Follow-up action | |

## 10. Counting rules

### Completed interview

Count when all of these exist:

- anonymised interview ID and date;
- participant role and cohort;
- one concrete workflow;
- current solution or explicit absence of one;
- problem and consequence;
- buyer/budget/trigger/deadline questions asked;
- private evidence reference.

Do not count invitations, scheduled calls, surveys without equivalent answers, networking conversations without the required fields, or repeated sessions with the same person about the same evidence as separate interviews.

### Problem confirmation

Mark **Yes** only when the interviewee provides:

1. a concrete problem in the relevant workflow;
2. a current workaround or explicit inability to handle it; and
3. a consequence such as delay, cost, manual work, risk, failed review, blocked launch, or lost conversion.

Mark **Unclear** when the concern is hypothetical, lacks a consequence, or comes mainly from the interviewer. Unclear does not count toward the threshold.

### Qualifying buyer/procurement signal

Mark **Yes** when the interview identifies at least one of:

- a specific budget-owning role or function;
- a concrete procurement trigger; or
- a decision or delivery deadline with a stated cause.

Praise, general interest, a request for updates, willingness to view a demo, or an unsigned expression of interest does not qualify.

## 11. G1 aggregate report template

Publish only anonymised counts and approved findings.

```markdown
## G1 buyer-gate decision — YYYY-MM-DD

### Counts

- Completed interviews: X / 20
- Unique organisations: X
- Problem confirmations: X / 8
- Buyer/procurement/deadline signals: X / 3

### Cohort mix

| Cohort | Interviews | Confirmations | Buyer signals |
|---|---:|---:|---:|
| Hospitality/service operators | | | |
| Integrators/service platforms | | | |
| Identity/privacy/security owners | | | |
| Other | | | |

### Repeated evidence

- Confirmed problem:
- Current workaround:
- Consequence:
- Economic buyer:
- Technical champion:
- Procurement trigger/deadline:
- Selected hospitality workflow:
- Price/procurement finding:
- Strongest contrary evidence:

### Decision

- [ ] PASS — all three G1 thresholds have qualifying evidence.
- [ ] MISS — at least one threshold lacks qualifying evidence.

If missed: pause broad product expansion and revise the buyer, workflow, or category hypothesis.

### Evidence handling

Private notes remain outside the public repository. Public entries contain anonymised counts and approved findings only.
```

## 12. Interviewer checklist

### Before

- [ ] Select cohort and role-specific module.
- [ ] Assign anonymised interview ID.
- [ ] Prepare private notes location.
- [ ] Keep product material closed during the problem section.
- [ ] Confirm 15- or 30-minute format.

### During

- [ ] Ask for consent to use anonymised findings.
- [ ] Ask permission separately before recording.
- [ ] Get one recent concrete workflow.
- [ ] Ask for problem, workaround, and consequence.
- [ ] Ask budget owner, procurement trigger, and deadline separately.
- [ ] Test price without discounting to zero.
- [ ] Run the concept test only after discovery questions.
- [ ] Ask for contrary evidence and a referral.

### After

- [ ] Complete the scorecard immediately.
- [ ] Separate quotes/observations from interviewer inference.
- [ ] Apply the counting rules.
- [ ] Store personal and confidential data privately.
- [ ] Update only anonymised aggregate counts in GitHub.
