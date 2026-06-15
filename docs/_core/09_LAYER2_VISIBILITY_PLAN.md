# Layer-2-Visibility — Plan: das „Hin und Her" sauber sichtbar machen

**Status: Aktiv (Plan, kein Code) | Stand: 2026-06-15**

> **Auftrag.** Entscheidung 1 = **A + B** ([`06_OPEN_DECISIONS.md`](06_OPEN_DECISIONS.md)).
> B = neutrale, lokale Sichtbarmachung für jeden Nutzer. Dieser Plan zeigt, wie wir das
> **additiv** umsetzen — **ohne wegzuwerfen, was schon da ist** — und dabei das Verlangen↔
> Offenlegen sauber anzeigen und die Rollen klar trennen.

> **Leitprinzip: additiv.** Bestehendes bleibt: `data-flow`-Engine, neutrale
> `summarizeTransaction()` (explizit *kein* Scoring), `DataFlowPanel`, `SovereigntyCenter`,
> WORM-`audit-log`. Wir reichen nur die **fehlende Seite** (verlangt/verweigert) durch und
> heben die Ansicht.

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

## 3. Verifizierte Ausgangslage (belegt, 2026-06-15)

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
  - **A** — `claimsWithheld` misst gegen *Policy-erlaubt*, nicht *Verifier-verlangt*
    (`WalletService.ts:1022` `claims_requested: req.allowed_claims`; `:1139` autorisiert).
  - **B** — ein **DENY** erzeugt keine Transaktion: `DataFlowService` liest **nur**
    `VP_GENERATED` (`data-flow/service.ts:41`); bei DENY gibt es kein `VP_GENERATED`.
    Das einzige `POLICY_EVALUATED`-Log (`WalletService.ts:1745`) trägt nur `result:'OVERRIDE'`.
  - **C** — Proximity/Offline-mdoc (ISO 18013-5, `WalletService.ts:1605`) loggt `VP_SENT`
    **ohne** `decision_id`/`claims_requested` → fällt aus der `decision_id`-Gruppierung → unsichtbar.
  - **D** — `DataFlowPanel` ist ein Demo-Toggle (`App.tsx:1711`, default `showDataFlow=false`),
    nicht „für jeden Nutzer".
  - **E** — kein Layer-2-Bezug in den Visibility-Komponenten (grep leer).

---

## 4. Umsetzung — PR-Schnitt (klein, TDD-fähig, je 1 PR)

### PR1 — Wurzel: ALLE `requested_claims` loggen (autorisiert **und** nicht-autorisiert)
*Das Muss.* An `evaluateRequest` (`:810`) auf **jedem** Verdict (ALLOW/PROMPT/**DENY**) ein
Audit-Event mit: `decision_id, verifier_did, requested_claims (alle, roh), authorized_claims,
denied_claims, verdict, reason_codes`.
→ Löst **A** (withheld misst gegen Roh-Anfrage) und **B** (DENY erzeugt jetzt einen Eintrag).

### PR2 — `data-flow` liest die neue Seite (additiv, nichts brechen)
- `DataFlowService.buildTransactions` zusätzlich das Policy-Event lesen → `claimsRequested`
  aus Roh-Anfrage, neues `deniedClaims`, Transaktionen **auch ohne `VP_GENERATED`** (DENY-Karten).
- `summarizeTransaction` um neutrale Sätze ergänzen: „Verifier verlangte X — nicht autorisiert: Y".
- Bestehende Felder/Tests bleiben (nullable → backward-compatible).

### PR3 — Gap C: Proximity/Offline-mdoc sichtbar
Dem Proximity-Pfad (`:1605`) `decision_id` + `claims_requested` mitgeben.

### PR4 — Surfacing (Gap D + E)
- `DataFlowPanel` von Demo-Toggle zur **erstklassigen, immer erreichbaren** Ansicht heben.
- **Layer-2-Hervorhebung** für vulnerable Kontexte (`minimumLayer === 2` →
  `docs/02-erwachsene-vulnerable`), wo Sichtbarkeit am meisten zählt.

---

## 5. Invarianten-Wächter (bei jedem PR)

- Neutral / **kein Scoring** (Transparenz, keine Bewertung).
- **Fail-Closed** bleibt; Mehrdeutigkeit = DENY.
- **Nichts Bestehendes entfernt** (additiv).
- Rollen-Trennung (Provider / Verifier / User / Convener) im Datenmodell durchgehalten.
- Honesty-Check: keine Behauptung über Daten, die nicht im Audit-Log belegt sind.

---

## 6. Offene Mini-Frage (vor PR1 zu verifizieren)

Trägt die `VerifierRequest` die **vollständige** rohe Claim-Liste — auch Claims, die **kein**
`authorized_requirement` trifft? `request_hash` (`policy.ts:307`) beweist, dass das Objekt zur
Capsule-Bauzeit vorliegt; die genaue Feldstruktur ist beim PR1-Scoping zu bestätigen
(erst schauen, dann Code).

---

*Bezug: [`06_OPEN_DECISIONS.md`](06_OPEN_DECISIONS.md) (Entsch. 1 = A+B), [`08_EU_BOUNDARIES.md`](08_EU_BOUNDARIES.md) (daneben-Positionierung), [`02_POLICY.md`](02_POLICY.md) (Convener, 5 Invarianten).*
