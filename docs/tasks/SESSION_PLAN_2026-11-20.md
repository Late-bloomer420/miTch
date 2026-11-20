# Session-Plan 2026-11-20 — Nach dem Massen-Merge (10 PRs, 0 offen)

Kontext: Alle mergebaren PRs wurden gemergt (#165, #178, #249, #265, #266, #301, #302, #304, #308, #309; master @ `8dd7f3e`). Der `Entire Gates`-Check schlägt wegen fehlender Entire-Credits auf jedem PR fehl, blockiert aber nicht.

## Die 5 Optionen

1. **Lokalen Branch `chore/session-22-history` aufräumen** — uncommitted/untracked Stand war gegen alten Base; gegen `origin/master` geprüft: alle lokalen Änderungen sind veraltete Regressionen (master hat jeweils mehr). Verwerfen, Branch auf master rebasen. *(gestartet)*
2. **Issue-Triage nach den Merges** — #296 (L2A-04, unlabeled synthetic receipts) gegen #301 (`21fc573`, `anchor.ts` setzt `network: 'mock'`, `status: 'mocked'` + Test) verifizieren und Evidence kommentieren. *(gestartet)*
3. **Nächste Security-Arbeit aus dem Backlog** — #293 (fail-closed bei Credentials ohne Status-Claim) oder #294 (echtes L2-Anchoring); #294 braucht zuerst das ADR aus #295 (Anchor-Backend-Wahl: TSA / OpenTimestamps / L2-Vertrag).
4. **CI-/Repo-Hygiene** — `Entire Gates` dokumentieren, solange keine Credits; Dependabot-/Audit-Ausnahmen (`scripts/security-audit-exceptions.json`, Ablauf 2026-12-18) im Blick behalten; #185 (High-Severity-Remediation) bleibt offen.
5. **QA-Evidence & Session-Doku aktualisieren** — `docs/qa/`-Referenzen, `STATE.md`, `SESSION_HISTORY.md` (Session 23: die 10 Merges nachtragen), CHANGELOG-Abgleich nach #309.

## Reihenfolge

1 → 2 → 5 (Doku zum Session-Ende) → 3 (neue Code-Arbeit) → 4 (kontinuierlich)
