# miTch — Outreach Starting List
## Innsbruck / Tirol — Discovery Conversations

> Goal: listen, not pitch. Understand their actual pain before showing anything.
> Student status at MCI is an asset — use it. "I'm researching this for a project" opens doors.

---

## Tier 1 — Start Here (highest signal, most accessible)

### 1. MCI itself
**Who:** Your own professors — specifically anyone in Digital Health, Health Management,
IT & Business Informatics, or Law & Governance departments.
**Why:** They are directly connected to every institution on this list. One warm intro from
a professor is worth 20 cold emails. They also deal with GDPR as a university themselves —
student data, research data, health studies.
**Ask:** "I'm working on a privacy middleware project. Who in the Tirol health or finance
sector would you think most benefits from reducing their GDPR data liability?"
**Also:** MCI has an entrepreneurship/innovation program (StartHub MCI). Talk to them early —
they can open doors and may have funding instruments.

### 2. Tirol Kliniken / LKH Innsbruck
**Who:** The Datenschutzbeauftragter (Data Protection Officer). Every hospital in the EU
must have one by law (GDPR Art. 37). This person's entire job is the problem miTch solves.
**Organisation:** Tilak GmbH (Tiroler Landeskrankenanstalten) — the operating company.
Headquartered in Innsbruck, runs LKH Innsbruck, LKH Hall, and others.
**Why:** Art. 9 special category health data is the highest-risk data category under GDPR.
Breach costs are enormous. They are under constant regulatory pressure. EHDS is coming.
**Ask:** "How do you currently handle minimal disclosure when staff or systems access patient data?
What does GDPR compliance cost you in time per month?"
**How to get in:** Email the DPO directly (listed in their GDPR notice / privacy policy on their
website — required by law). Reference your MCI student status and the research angle.

### 3. UMIT TIROL (Hall bei Innsbruck)
**Who:** Researchers in Health Informatics or eHealth.
**What:** Private University for Health Sciences, Medical Informatics and Technology.
Directly adjacent to your topic — digital health data, patient privacy, EHDS.
**Why:** University researchers are easier to get meetings with than hospital administrators.
They think about exactly these problems academically and have institutional connections.
They may also be interested in research collaboration.
**How:** Direct email to a relevant department. Student-to-researcher outreach works well here.

---

## Tier 2 — High Value, Slightly More Effort to Access

### 4. Hypo Tirol Bank
**Who:** Compliance officer or Digital/IT department.
**Why:** Regional bank headquartered in Innsbruck. PSD2 open banking is their regulatory
reality. They hold enormous amounts of personal data. GDPR liability is real to them.
A "forgetting layer" that reduces what they store = reduced breach liability = reduced cost.
**How:** Look for their Datenschutzbeauftragter in their privacy notice. Or approach via
WKO Tirol which has existing relationships with regional banks.

### 5. Raiffeisenbank / Sparkasse Tirol
Same angle as Hypo Tirol. Raiffeisen is a cooperative structure — often more open to
regional innovation conversations than large national banks.

### 6. Local Pharmacies
**Who:** Owner/manager of any independent pharmacy in Innsbruck.
**Why:** The age verification use case is immediate and concrete. They handle
prescription data (special category under GDPR), age-restricted products, and have
daily compliance friction. No procurement process — the owner decides.
**Ask:** "What do you do today when someone buys something age-restricted online or at the counter?
What's the risk if you get it wrong?"
**How:** Walk in. Literally. This is the kind of conversation that happens in person.

### 7. Data Protection Lawyers in Innsbruck
**Who:** IT/GDPR-focused lawyers. Search Rechtsanwaltskammer Tirol (Tyrolean Bar Association)
for "Datenschutz" or "IT-Recht" specialists.
**Why:** They advise the hospitals, banks, and businesses you want to reach.
They know what's actually being enforced and what clients are scared of right now.
They are also potential channel partners — if they see miTch as something their clients need,
they refer you. One lawyer who believes in what you're building reaches 50 institutions.
**Ask:** "What GDPR issue is your clients asking about most right now? What would they pay
to solve?"

### 8. Tigewosi / NHT Tirol (Social Housing / Hausverwaltungen)
**Who:** IT or compliance contact at Tigewosi (Tiroler Gemeinnützige Wohnungsbau- und
Siedlungsgesellschaft) or NHT (Neue Heimat Tirol).
**Why:** Housing companies collect enormous amounts of sensitive data: Lohnzettel (payslips),
Meldezettel (registration documents), Mietverträge, bank statements.
Under GDPR, they must justify every field they collect. If miTch acts as the forgetting layer,
they get the verification result (e.g. "rent covered for 6 months") without storing the
applicant's bank statements — zero breach liability for that data.
The DSGVO argument is concrete and immediate: "You hold no Lohnzettel → smaller data risk."
**Use case:** Tenant applies for a WG-Zimmer. miTch generates a PSD2-based proof:
`Miete für 6 Monate gedeckt` — landlord gets the answer, never sees the account balance.
**Ask:** "How long do you retain tenant income documents after a tenancy decision?
What would it mean for your liability if you didn't need to retain them at all?"
**How:** Email the Datenschutzbeauftragter listed in their GDPR privacy notice.

### 9. Tourism / Ski Pass Verifier (Einheimischentarife)
**Who:** Manager at a ski resort ticket office (e.g. Nordkette, Stubai, Axamer Lizum)
or tourist information office (Innsbruck Tourismus).
**Why:** "Einheimischentarife" (resident rates) require proof of local registration.
Currently: show Meldezettel (registration document) — full home address, DOB, date of
registration — just to get a cheaper lift ticket.
miTch proof: `Registered in Innsbruck: ✓` — from ID Austria / Melderegister.
No address, no DOB, no surname shared.
**Use case:** Same flow as student discount — QR scan at the lift, single-use proof,
session expires in minutes. No data retained at the resort.
**Ask:** "How do you currently verify Einheimischen status? How many staff-minutes does it cost per day?"
**How:** Walk in during off-peak hours. Ticket office staff see this daily — they know the friction.

---

## Tier 3 — Ecosystem & Support (less urgent but useful)

### 8. Standortagentur Tirol
Tyrolean economic development agency. Runs programs for startups and innovation projects.
They can connect you to industry, point you toward funding, and open institutional doors
you couldn't open alone. They want to promote Tyrolean tech projects.

### 9. WKO Tirol (Wirtschaftskammer Tirol)
The regional chamber of commerce. Has a Fachgruppe for IT/Digitalwirtschaft.
Useful for understanding the small-business landscape (pharmacies, local businesses)
and for events where you can meet relevant people informally.

### 10. University of Innsbruck — Institut für Informatik
Researchers working on security, privacy, distributed systems.
Useful for research validation, potential academic collaboration, and credibility.
A research paper co-authored with a Uni Innsbruck professor carries weight in institutional conversations.

---

## What to Say (the one paragraph — in German if needed)

> "Ich entwickle eine Privacy-Middleware, die es Institutionen ermöglicht, bei
> Verifizierungsprozessen nur die Mindestdaten zu teilen — und diese danach
> kryptografisch zu löschen. Das reduziert die DSGVO-Haftung konkret: weniger
> gespeicherte Daten bedeuten kleineres Risiko bei Datenpannen. Ich bin Student
> am MCI und suche Gesprächspartner aus dem Gesundheits- und Finanzbereich,
> die mir helfen zu verstehen, wo der tatsächliche Schmerz liegt.
> Wären Sie bereit für 30 Minuten?"

English version:
> "I'm building a privacy middleware that lets institutions share only the minimum
> data needed at a verification step — and then cryptographically destroy the session.
> That reduces GDPR liability concretely: less data held means less risk in a breach.
> I'm a student at MCI and I'm looking for people in health and finance who can help
> me understand where the actual pain is. Would you be open to 30 minutes?"

---

## Rules for These Conversations

1. **Listen 80%, talk 20%.** You are there to learn, not to sell.
2. **Don't explain the technology** until they ask. Lead with the problem, not the solution.
3. **Ask about their current process** — how do they handle it today, what does it cost,
   what worries them. The gap between today and what they want is your product.
4. **Take notes immediately after.** What exact words did they use for the problem?
   Those words become your pitch language later.
5. **Always ask:** "Who else should I be talking to?" One good conversation leads to three more.
6. **Be honest about where you are.** Working prototype. Looking for a pilot partner.
   Not a finished product yet. That's fine — say it directly.

---

## What You're NOT Doing Yet

- Not asking anyone to sign anything
- Not quoting prices
- Not promising timelines
- Not claiming production-readiness you don't have

That comes after you've had 10–15 of these conversations and know exactly what to build next.

---

## Questions for Your MCI Professor

Use these depending on which department they're from.
The goal is not to get answers — it's to get introductions and to be taken seriously.
Show you've already thought deeply. Ask where their thinking goes next.

---

### For any professor — opening questions

**German:**
> „Ich entwickle gerade ein Datenschutz-Middleware-Projekt, das auf selektiver Offenlegung
> und kryptografischer Datenlöschung basiert — also Institutionen helfen soll, nur die
> Mindestdaten zu teilen und den Rest direkt zu vergessen. Welche Institutionen hier in Tirol
> würden Ihrer Meinung nach am meisten davon profitieren, weniger Daten zu halten?"

> „Ich frage mich, ob das größte Problem auf der Seite der Institutionen liegt —
> die zu viele Daten speichern und das Haftungsrisiko tragen — oder auf der Seite
> der Nutzer, die keine Transparenz haben. Wo sehen Sie den dringenderen Bedarf?"

**English:**
> "I'm building a privacy middleware project based on selective disclosure and
> cryptographic data deletion — helping institutions share only the minimum and forget
> the rest. In your view, which institutions in Tirol would benefit most from holding less data?"

> "I'm trying to figure out whether the bigger problem is on the institutional side —
> organisations storing too much and carrying the liability — or on the user side —
> people having no visibility into what's being collected. Where do you see the more
> urgent need?"

---

### For Health Management / Digital Health professors

**German:**
> „EHDS verpflichtet Gesundheitseinrichtungen ab 2025–2026, Patienten elektronischen
> Zugang zu ihren Daten zu geben. Wie gut sind die Tiroler Kliniken Ihrer Einschätzung
> nach darauf vorbereitet? Und wer bei Tirol Kliniken wäre der richtige Ansprechpartner,
> um das aus erster Hand zu verstehen?"

> „Elga ist in Österreich schon weiter als in den meisten EU-Ländern. Sehen Sie das als
> Chance für Tiroler Unternehmen, früher als andere in diesem Bereich aktiv zu werden?"

**English:**
> "EHDS requires health institutions to give patients electronic access to their data
> from 2025–2026. In your view, how prepared are Tirolean clinics for that? And who
> at Tirol Kliniken would be the right person to understand that first-hand?"

> "Austria is ahead of most EU countries with Elga. Do you see that as an opportunity
> for Tirolean companies to move earlier than others in this space?"

---

### For Law / GDPR / Compliance professors

**German:**
> „Aus Ihrer Sicht als Rechtswissenschaftler: Wo liegt bei der DSGVO-Durchsetzung
> aktuell der größte praktische Schmerzpunkt für Institutionen — also das, wofür sie
> tatsächlich haften und was sie nachts wach hält?"

> „Der EU AI Act gibt Betroffenen ab 2025 das Recht auf Erklärung automatisierter
> Entscheidungen bei Hochrisiko-KI-Systemen. Glauben Sie, dass Institutionen in
> Österreich darauf vorbereitet sind — und wer würde ihnen dabei helfen, das umzusetzen?"

> „Es gibt eine Grauzone zwischen Daten, die Nutzer aktiv bereitgestellt haben, und
> Daten, die Institutionen über sie ableiten — sogenannte Schattenprofile. Die DSGVO
> Art. 20 deckt das nicht ab. Sehen Sie rechtliche Entwicklungen, die das ändern könnten?"

**English:**
> "From a legal perspective, where is the biggest practical pain point in GDPR
> enforcement for institutions right now — what are they actually being held liable
> for, and what keeps them up at night?"

> "The EU AI Act gives individuals the right to explanations of automated decisions
> in high-risk AI systems from 2025. Do you think Austrian institutions are prepared
> for that — and who would help them implement it?"

> "There's a grey zone between data users actively provided and data institutions
> derived or inferred about them — shadow profiles. GDPR Art. 20 doesn't cover that.
> Do you see legal developments that might change this?"

---

### For IT / Technology / Informatics professors

**German:**
> „Ich habe mich mit dem EUDIW-Architekturrahmen beschäftigt und bin auf ein
> Unlinkability-Problem gestoßen: das Wallet Instance Attestation schafft eine
> Gerätekorrelation, die cross-verifier Tracking ermöglicht — eigentlich das Gegenteil
> des Ziels. Wie beurteilen Sie den aktuellen Stand der EUDIW-Spezifikation?"

> „Für die Dateneinsicht auf Nutzerseite denke ich an Bulletproofs für Range Proofs —
> also beweisen, dass ein Wert in einem Bereich liegt, ohne den genauen Wert preiszugeben.
> Ist das Ihrer Meinung nach auf mobiler Hardware heute schon praktisch einsetzbar,
> oder ist das noch 3–5 Jahre entfernt?"

**English:**
> "I've been looking at the EUDIW Architecture Reference Framework and found an
> unlinkability issue — the Wallet Instance Attestation creates a device correlation
> that enables cross-verifier tracking, which is the opposite of its stated goal.
> How do you assess the current state of the EUDIW spec?"

> "For user-side data insight, I'm thinking about Bulletproofs for range proofs —
> proving a value is within a range without revealing the exact value. In your view,
> is that practically deployable on mobile hardware today, or is it still 3–5 years out?"

---

### The closing question — always ask this last

**German:**
> „Mit wem sollte ich unbedingt noch sprechen? Wen kennen Sie, der dieses Problem
> aus erster Hand erlebt — also zum Beispiel einen Datenschutzbeauftragten bei
> Tirol Kliniken, einen Compliance-Verantwortlichen bei einer Bank, oder einen
> auf DSGVO spezialisierten Anwalt hier in Innsbruck?"

**English:**
> "Who else should I absolutely be talking to? Do you know someone who experiences
> this problem first-hand — for example a Data Protection Officer at Tirol Kliniken,
> a compliance lead at a bank, or a GDPR-specialist lawyer here in Innsbruck?"

---

### Why these questions work

- They show you've already done your homework — EUDIW ARF, Bulletproofs, EHDS dates, AI Act.
  Professors respect students who arrive prepared.
- They are genuinely open — you don't know the answers, and neither do they with certainty.
  That makes it a real conversation, not an interview.
- The closing question is the most important one in the whole conversation.
  One warm intro from a professor lands you directly in the room with the right person.
