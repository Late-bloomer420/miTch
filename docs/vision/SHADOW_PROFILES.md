# miTch — Shadow Profiles: The Hard Limit and the Partial Lever

> Not implementation-ready. Thinking space only.

---

## What Shadow Profiles Are

Institutions hold two kinds of data about you:

**Data you gave them directly:**
- Your name, address, date of birth — provided at signup
- Your transactions — recorded as you made them
- Your health records — created during treatment
- This data is covered by GDPR Art. 20 (portability) and Art. 15 (access)

**Data they inferred or derived about you — the shadow profile:**
- Your bank inferred your religion from charitable donation patterns
- Your insurer inferred health conditions from pharmacy purchase history
- Your credit card company inferred political views from spending behaviour
- Your social platform built a psychological model from engagement patterns
- Data brokers compiled profiles from dozens of sources you never directly interacted with
- Your fitness app inferred fertility cycles, sleep disorders, mental health indicators

This inferred/derived data:
- Is often more accurate than what you'd voluntarily disclose
- Is the most commercially valuable data institutions hold about you
- Drives the automated decisions that most affect your life (credit, insurance, employment, healthcare)
- Is currently NOT covered by GDPR Art. 20 — it's proprietary inference, not data you provided
- Cannot be accessed, corrected, or challenged under most current EU law

---

## The Honest Boundary

**Shadow profiles are the hard limit of what miTch can address today.**

The forgetting layer (Layer 1) controls what leaves your wallet at a transaction checkpoint.
It cannot reach back into the inferred profiles institutions have already built.

The local insight engine (Layer 2) lets you run the same models on your own data.
It cannot access what institutions have inferred — only what you have access to.

miTch is honest about this limit. The daily review shows:
- What you shared deliberately (controlled by miTch)
- What the platform layer could observe (OS/browser/network telemetry — shown, not fixable)
- What decisions were made about you using AI systems (partially visible via AI Act)

It does not claim to show the full shadow profile. That would be dishonest.

---

## The Partial Lever: EU AI Act

The EU AI Act (in force since August 2025) is the most significant regulation for the shadow profile problem, though it only partially addresses it.

### What the AI Act requires (high-risk AI systems):

High-risk categories include: credit scoring, insurance risk assessment, employment screening,
access to healthcare, access to education, border control, administration of justice.

For these systems, providers must:
1. Provide "meaningful information about the logic involved" in automated decisions
2. Allow individuals to request an explanation of decisions that significantly affect them
3. Maintain documentation of training data, model design, and risk assessment

### What this means in practice:

If a bank denies your loan using an AI model → you can request an explanation.
If an insurer raises your premium using an AI model → you can request an explanation.
If an employer rejects your application via automated screening → you can request an explanation.

That explanation — if it mentions which data points drove the decision — gives you a window
into what they know about you. Not the full profile. The output side of it.

**Example:**
> "Your application was declined primarily due to: high revolving credit utilisation (42%),
> three recent credit enquiries in 90 days, and irregular income pattern."

You can now see: they know your utilisation, your enquiry history, and your income pattern.
You didn't know they had all three. Now you do. That's a piece of the shadow profile made visible.

---

## How miTch Uses This

### Feature: AI Act Explanation Requests

When a user receives a significant automated decision (loan denial, insurance premium change,
employment rejection), miTch helps them:

1. **Identify the right:** "This decision may have been made by a high-risk AI system.
   Under the EU AI Act, you have the right to request an explanation."

2. **Generate the request:** Pre-filled formal request using the institution's required
   contact channel, citing the AI Act and the specific decision.

3. **Store the response:** The explanation is stored as a signed entry in the audit log —
   part of the user's permanent evidence record alongside consent receipts.

4. **Build the picture over time:** Multiple explanations from the same institution,
   accumulated over months, start to reveal what data points they consistently use.
   Not the full model. Not the training data. But a pattern the user can see and reason about.

5. **Escalate if refused:** If the institution doesn't respond or refuses without valid reason,
   the daily review flags it as 🔴 Danger and offers the DPA escalation path.

---

## The Advocacy Frontier

Full transparency of shadow profiles — the right to see your inferred profile, not just
the data you provided — requires new regulation that doesn't exist yet.

What would that regulation look like:
- An extension of GDPR Art. 15 (right of access) to explicitly cover derived/inferred data
- A "right to your inferred profile" — similar to the right to access raw data, but for conclusions
- Mandatory model cards: institutions must publish what categories of inference their AI systems perform

This does not exist in current EU law. The AI Act's explanation right is narrower — it covers
individual decisions, not standing profiles.

**miTch's role at this frontier:**
- Document the gap clearly to users: "This is what we can show you. This is what no one can show you yet."
- Accumulate AI Act explanation responses as evidence of what's being inferred
- Over time, that evidence base supports the advocacy case for stronger regulation
- Connect users to digital rights organisations (e.g. noyb — Max Schrems, Vienna) who are
  pushing exactly this frontier through strategic litigation

---

## noyb — Network of European Data Rights Lawyers (Vienna)

noyb (None Of Your Business) is the most active GDPR enforcement organisation in Europe.
Founded by Max Schrems (Austrian). Headquartered in Vienna — relevant for Innsbruck proximity.

They have filed hundreds of GDPR complaints across the EU, including against shadow profiling
and inferred data practices. They are the strategic litigation arm for exactly the regulatory
frontier that miTch sits at.

Connection opportunity: miTch's evidence layer (consent receipts, AI Act explanation log)
produces exactly the kind of documented evidence that supports noyb's complaint filings.
A data collaboration or referral relationship with noyb is worth exploring — not as a
commercial partner, but as a shared mission alignment.
