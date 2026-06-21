# Layer-2-Visibility — Plan: das „Hin und Her" sauber sichtbar machen

**Status: Umgesetzt für G-140.1 (#112/#114/#115/#116) | Stand: 2026-06-21**

> **Auftrag.** Entscheidung 1 = **A + B** ([`06_OPEN_DECISIONS.md`](06_OPEN_DECISIONS.md)).
> B = neutrale, lokale Sichtbarmachung für jeden Nutzer. Dieser Plan zeigt, wie wir das
> **additiv** umsetzen — **ohne wegzuwerfen, was schon da ist** — und dabei das Verlangen↔
> Offenlegen sauber anzeigen und die Rollen klar trennen.

> **Leitprinzip: additiv.** Bestehendes bleibt: `data-flow`-Engine, neutrale
> `summarizeTransaction()` (explizit *kein* Scoring), `DataFlowPanel`, `SovereigntyCenter`,
> WORM-`audit-log`. Wir reichen nur die **fehlende Seite** (verlangt/verweigert) durch und
> heben die Ansicht.

> **⚠️ Begriffsklärung „Layer 2" (nach Re-Scan 2026-06-16, belegt — vorher verwechselt).**
> Es gibt im Repo **zwei** „Layer 2" auf verschiedenen Achsen:
> 1. **Produkt-Architektur** (`specs/35_Product_Architecture_Layers.md`): Core → **Shield** →
>    Orchestrator. **Layer 2 = „miTch Shield"** = *„Web request visibility (who asks for what),
>    user notifications, block/allow/notify"*. Die konkrete Roadmap dafür ist
>    `specs/36_Phase2_Shield_and_AI_Orchestration_Roadmap.md`, **Track A1 „Visibility Baseline"**
>    (data-request events by site/service · sensitivity low/med/high · user event timeline,
>    *local-first*). **Das ist dieses „Layer 2 Visibility".**
> 2. **Daten-Sensitivität** (`layer-resolver`, Policy `minimumLayer`): Layer 0/1/2 =
>    WELT/GRUNDVERSORGUNG/**VULNERABLE**. Eigene Achse; der Ordner `docs/02-erwachsene-vulnerable`
>    ist aktuell **leer** — die Semantik lebt im Code, nicht dort. Vulnerable ist hier nur ein
>    *Sensitivitäts-Input* für A1, **nicht** die Definition von „Layer 2".
>
> **Phase-Spannung (ehrlich):** `specs/36` setzt Shield formal als **Phase 2 „erst nach Core-Pilot-Go"**.
> Entscheidung 1 (**A+B parallel**) startet die User-Sichtbarkeit *früher*. Bewusste Abweichung.

---

## 1. Rollen — sauber getrennt (Kernanforderung)

Genau drei externe Rollen + Convener, in **Datenmodell und UI** getrennt:

| Rolle | Bedeutung | Code-Heimat |
|---|---|---|
| **Provider / Issuer** | stellt Credentials aus | `issuer-mock`, `eid-issuer-connector` |
| **Verifier** | *verlangt* Claims | OID4VP-Request → `requested_claims` |
| **User / Holder** | besitzt, entscheidet, *sieht* | `wallet-pwa`, `wallet-core` |
| **miTch = Convener** | setzt Regeln + erzwingt sie + macht sichtbar | `policy-engine`, `data-flow` |

miTch ist **kein** Issuer und **kein** Verifier (bindend, [`02_POLICY.md`](02_POLICY.md)).
Vertrauen = überprüfbar festgelegt, *was niemand wissen darf* — nicht, dass miTch etwas weiß.

---

## 2. Das „Hin und Her" — drei Stufen pro Transaktion

Jede Transaktion wird in drei klar getrennten Stufen dargestellt:

| ① Verifier verlangte | ② miTch entschied | ③ User gab (aus Provider-Credential) |
|---|---|---|
| **alle** `requested_claims` (roh, vor Policy) | `authorized` vs **`denied`** + `verdict` + `reasonCode` | `claims_shared` + `proven_claims` |

Daraus wird „zurückgehalten" **ehrlich** = *roh-verlangt − geteilt* — inklusive der von der
Policy verweigerten Claims. **Over-Asking wird damit sichtbar**, statt von der Policy vorher
stillschweigend weggestrichen zu werden.

---

## 3. Verifizierte Ausgangslage (belegt, 2026-06-15, re-verifiziert 2026-06-16)

- **Vorarbeit existiert — NICHT neu erfinden:** Das **Identity-Firewall-MVP** (Sprint 01,
  Abschlussreview 2026-06-07, `STATE.md`, `docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md`) hat das
  Sichtbarkeits-Substrat bereits gebaut: `IDENTITY_ACCESS_DETECTED`-Audit-Events, PII-minimale
  `IdentityFirewallMetadata`, DataFlow-`identity`-Kategorie/Badge — **explizit „visibility, not
  blocking", 230 grüne Tests** (data-flow allein 56). Dieser Plan **erweitert** das.
- **Bereits geschriebene Anforderung (PR1 ist kein neues Feature):**
  `specs/04_Data_Flows_and_PII_Boundaries.md` schreibt fail-closed: *„RP asks for unnecessary
  attributes => DENY or require user explicit override (and **log it locally**)."* Plus
  `specs/36` Track A2: *„Tamper-evident local activity log."*
- **Deny-Vokabular existiert — wiederverwenden, nicht erfinden:** deterministische Deny-Reason-Codes
  (`policy-engine`) + Deny-Kategorie-KPIs (`specs/65_KPI_Deny_Category_Visibility.md`). DENY-Karten
  daran ausrichten.
- **Companion-Open-Item:** Pilot-Finding **AI-04 „Audit-Export-Format/Schema nicht spezifiziert"**
  (Open P1, `docs/pilot/PILOT_DRY_RUN_01_FINDINGS.md`) berührt direkt die neuen Audit-Events —
  gemeinsam mitdenken.
- **Engine existiert & ist neutral:** `data-flow/summary.ts` → *„No speculation, no risk
  scoring — just facts the user can verify."*
- **Daten existieren upstream, werden aber nicht geloggt:**
  - `WalletService.evaluateRequest()` (`services/WalletService.ts:810`) ist der **einzige
    Chokepoint**, an dem die rohe `VerifierRequest` UND das `PolicyEvaluationResult`
    (`verdict`, `reasonCodes`, `deniedClaims`, Capsule) zusammenkommen.
  - `Decision.deniedClaims` wird gerechnet (`shared-types/policy.ts:107`).
  - `DecisionCapsule.authorized_requirements[].requested_claims?` ist im Kommentar bereits
    *„for audit completeness / claimsWithheld"* vorgesehen (`shared-types/policy.ts:329`).
- **Verifizierte Lücken:**
  - **A — geschlossen mit #112/#114** — `claimsWithheld` misst gegen *Policy-erlaubt*, nicht *Verifier-verlangt*
    (`WalletService.ts:1022` `claims_requested: req.allowed_claims`; `:1139` autorisiert).
  - **B — geschlossen mit #112/#114** — ein **DENY** erzeugt keine Transaktion: `DataFlowService` liest **nur**
    `VP_GENERATED` (`data-flow/service.ts:41`); bei DENY gibt es kein `VP_GENERATED`.
    Das einzige `POLICY_EVALUATED`-Log (`WalletService.ts:1745`) trägt nur `result:'OVERRIDE'`.
  - **C — geschlossen mit #115/#116** — Proximity/Offline-mdoc (ISO 18013-5, `WalletService.ts:1605`) loggt `VP_SENT`
    **ohne** `decision_id`/`claims_requested` → fällt aus der `decision_id`-Gruppierung → unsichtbar. #116 routet proximity zusätzlich vor Disclosure durch Policy.
  - **D — zukünftiges Surfacing-Thema, nicht Teil von G-140.1-Codekette** — `DataFlowPanel` ist ein Demo-Toggle (`App.tsx:1711`, default `showDataFlow=false`),
    nicht „für jeden Nutzer".
  - **E — zukünftiges Surfacing-Thema, nicht Teil von G-140.1-Codekette** — kein Layer-2-Bezug in den Visibility-Komponenten (grep leer).

---

## 4. Umsetzung — PR-Schnitt (klein, TDD-fähig, je 1 PR)

### PR1 — Wurzel: ALLE `requested_claims` loggen (autorisiert **und** nicht-autorisiert)
**Geliefert mit #112.**
*Das Muss.* An `evaluateRequest` (`:810`) auf **jedem** Verdict (ALLOW/PROMPT/**DENY**) ein
Audit-Event mit: `decision_id, verifier_did, requested_claims (alle, roh), authorized_claims,
denied_claims, verdict, reason_codes`.
→ Löst **A** (withheld misst gegen Roh-Anfrage) und **B** (DENY erzeugt jetzt einen Eintrag).

### PR2 — `data-flow` liest die neue Seite (additiv, nichts brechen)
**Geliefert mit #114.**
- `DataFlowService.buildTransactions` zusätzlich das Policy-Event lesen → `claimsRequested`
  aus Roh-Anfrage, neues `deniedClaims`, Transaktionen **auch ohne `VP_GENERATED`** (DENY-Karten).
- `summarizeTransaction` um neutrale Sätze ergänzen: „Verifier verlangte X — nicht autorisiert: Y".
- Bestehende Felder/Tests bleiben (nullable → backward-compatible).

### PR3 — Gap C: Proximity/Offline-mdoc sichtbar
**Geliefert mit #115.**
Dem Proximity-Pfad (`:1605`) `decision_id` + `claims_requested` mitgeben.

### PR4 — Proximity policy routing
**Geliefert mit #116.**
- Proximity mdoc Requests werden vor Disclosure in `evaluateRequest()` geroutet.
- `POLICY_EVALUATED` und `VP_SENT` teilen denselben Entscheidunganker.
- Demo-Regel `did:askmi:proximity-reader` erlaubt exakt `given_name` + `family_name`.
- Over-Ask wird nicht offengelegt; DENY bleibt sichtbar mit `claims_shared: []`.

### Follow-up — Surfacing (Gap D + E)
**Nicht Teil der geschlossenen G-140.1-Kette; nur starten, wenn konkret priorisiert.**
- `DataFlowPanel` von Demo-Toggle zur **erstklassigen, immer erreichbaren** Ansicht heben.
- **Sensitivitäts-Klassifikation** (`specs/36` Track A1: low/med/high), in die `minimumLayer`
  (inkl. Layer 2 = vulnerable) als *ein* Input einfließt — nicht als „Layer 2"-Definition.

---

## 5. Invarianten-Wächter (bei jedem PR)

- Neutral / **kein Scoring** (Transparenz, keine Bewertung).
- **Fail-Closed** bleibt; Mehrdeutigkeit = DENY.
- **Nichts Bestehendes entfernt** (additiv).
- Rollen-Trennung (Provider / Verifier / User / Convener) im Datenmodell durchgehalten.
- Honesty-Check: keine Behauptung über Daten, die nicht im Audit-Log belegt sind.

---

## 6. Geklärte Mini-Frage (PR1/#112)

Trägt die `VerifierRequest` die **vollständige** rohe Claim-Liste — auch Claims, die **kein**
`authorized_requirement` trifft? `request_hash` (`policy.ts:307`) beweist, dass das Objekt zur
Capsule-Bauzeit vorliegt. In #112 verifiziert: `VerifierRequest.requirements[].requestedClaims`
trägt die rohe Claim-Liste; `WalletService.collectRequestedClaims()` sammelt Requirements +
Legacy-Felder und de-dupliziert namenbasiert.

---

*Bezug: [`06_OPEN_DECISIONS.md`](06_OPEN_DECISIONS.md) (Entsch. 1 = A+B), [`08_EU_BOUNDARIES.md`](08_EU_BOUNDARIES.md) (daneben-Positionierung), [`02_POLICY.md`](02_POLICY.md) (Convener, 5 Invarianten).*
