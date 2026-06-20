# miTch — Offene Entscheidungen

**Aktive Entscheidungen die getroffen werden müssen. Stand: 02.05.2026**

---

## Entscheidung 1: Produktfokus (KRITISCH)

**Frage:** Produkt A only / Produkt B only / A+B parallel?

| Option | Was | Vorteil | Risiko |
|---|---|---|---|
| **A only** | Verifier-Side Compliance-as-a-Service | Klarer B2B-Revenue, regulierte Märkte | Kein Nutzer-Produkt |
| **B only** | User-Side Selbstkenntnis-Schicht | Direkter Nutzernutzen | Schwieriges Business Model |
| **A+B** | Beide parallel | Vollständiger Ansatz | Überdehnung, zu wenig Fokus |

**Status: ENTSCHIEDEN (2026-06-15): A **und** B parallel.**  
Verifier-Side Compliance-as-a-Service (A) *und* User-Side Selbstkenntnis/Sichtbarmachung (B).
Erster konkreter B-Schritt: Layer-2-Visibility (neutrale, lokale Sichtbarmachung), siehe
[`08_EU_BOUNDARIES.md`](08_EU_BOUNDARIES.md).
*(Vorherige Empfehlung war „A zuerst" — vom Nutzer überstimmt zugunsten A+B.)*

---

## Entscheidung 2: Positionierung nach EU Age Verification App

**Frage:** Ist miTch ein Altersverifikations-Tool oder Compliance-Infrastruktur für regulierte Märkte?

- Option A: Age Verification ist Beachhead (konkurriert mit EU-App = verliert)
- Option B: miTch ist der **Policy Layer über** der EU-App (EU-App = Zulieferer, miTch = Enforcement)

**Status: GEKLÄRT (2026-06-15): daneben, nicht darüber/dagegen.**  
miTch konkurriert nicht mit der EU-App und positioniert sich auch nicht als Hierarchie *über* ihr,
sondern **daneben**: es ergänzt die proven EU-Schienen (EUDI Wallet, EU Age App, EU Business Wallet)
genau dort, wo sie strukturell aufhören (Zweckbindung/Enforcement + neutrale Sichtbarmachung *nach*
der Offenlegung). Voraussetzung: die exakten Grenzen der EU-Systeme stehen belegt fest →
[`08_EU_BOUNDARIES.md`](08_EU_BOUNDARIES.md) (das Fundament).

---

## Entscheidung 3: Erster zahlender Kunde

**Frage:** Welches Segment adressieren wir als erstes?

Kandidaten (nach Zahlungsbereitschaft):
1. Sportwetten-Plattformen (GlüStV-Compliance, DSGVO)
2. Adult Content (DSA Art. 28, DE/FR Enforcement)
3. Health / Telemedicine (DSGVO Art. 9)

**Status: Nicht entschieden.** Braucht einen konkreten Pilot-Partner.

---

## Entscheidung 4: Finanzierungsmodell

**Frage:** Kommerziell (Verifier zahlen) oder öffentliche Förderung?

- Commercial: Sofortiger Revenue-Druck; braucht Pilot-Kunden
- Förderung (DEP, Horizon Europe, FFG): Weniger Druck; braucht akademischen Partner + Antrag
- Hybrid: Förderung für Basis-Infrastruktur + Commercial für regulierte Märkte

**Status: Nicht entschieden.** Förderantrag würde mindestens 3-6 Monate dauern.

---

## Entscheidung 5: Privacy Revocation Design

**Frage:** Wie wird Revocation für regulierte Märkte implementiert?

Regulierte Märkte (Sportwetten, Health) brauchen:
- Selbstsperren überprüfbar machen OHNE zentrale Profildatenbank
- Das ist technisch komplex und nicht im MVP implementiert

**Status: Design offen.** Priorität erhöhen wenn Sportwetten-Pilot konkret wird.

---

## Entscheidung 6: Code-Audit STABLE packages

**Empfehlung aus Inventur (02.05.2026):** `@askmi/shared-crypto` und `@askmi/policy-engine` sollten vor erster kommerzieller Nutzung unabhängig auditiert werden.

**Status: Ausstehend.**

---

## Nächste Sitzung sollte klären:

- [ ] Entscheidung 1 (Produktfokus) formal treffen
- [ ] Entscheidung 2 (Positionierung) formal treffen  
- [ ] Ersten Pilot-Kandidaten identifizieren (Entscheidung 3)
