# Archiv-Inventar: Pakete und Doku-Ordner — 2026-11-11

Entscheidungsgrundlage dafür, was im Arbeitsbaum bleibt und was ins Archiv geht.
**Dieser PR verschiebt und löscht nichts.** Der Owner entscheidet pro Zeile; erst danach
folgt je Entscheidung ein eigener PR.

|             |                                                                                                                                                                        |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Quellstand  | `master` `002ce5e65b967e883773392ac455920ab4882643`                                                                                                                    |
| Gemessen am | 2026-11-10, Node v22.23.4, pnpm 9.15.9, Linux                                                                                                                          |
| Testlauf    | `pnpm test`: 2408 bestanden, 1 übersprungen (49 Turbo-Tasks)                                                                                                           |
| Abgrenzung  | Beleg-Orte (`docs/qa/`, `docs/ops/`, `docs/pilot/`, `docs/security/`, `data/evidence/`, Indizes) gehören zu DOC-02 (#253) und werden hier nur genannt, nicht bewertet. |

## Maßstab

Ein Paket gilt als **genutzt**, wenn eine der vier startbaren Anwendungen es im Quellcode
importiert, direkt oder über andere Pakete: `wallet-pwa`, `issuer-mock`, `verifier-backend`,
`verifier-frontend`. Importe aus Testdateien zählen nicht als Nutzung und sind getrennt
ausgewiesen.

„Getestet“ und „genutzt“ sind zwei verschiedene Aussagen. Ein Paket kann eigene grüne Tests
haben und trotzdem von keiner Anwendung ausgeführt werden.

## Ergebnis Pakete

|                                     | Pakete | Zeilen Code | Tests in `pnpm test` |
| ----------------------------------- | -----: | ----------: | -------------------: |
| Von einer Anwendung genutzt         |     14 |      23.942 |                1.436 |
| Von keiner Anwendung genutzt        |     17 |      12.537 |                  474 |
| davon Vorschlag „behalten“          |      3 |         502 |                   92 |
| davon Vorschlag „Owner entscheidet“ |      5 |       2.831 |                  159 |
| davon Vorschlag „archivieren“       |      9 |       9.204 |                  223 |

Die übrigen 498 der 2408 Tests liegen in den vier Anwendungen selbst. Zeilen sind Zeilen in
`.ts`/`.tsx`-Dateien ohne Testdateien, Leerzeilen eingeschlossen.

Vier Pakete führen in `pnpm test` keine Tests aus: `benchmarks` und `demo-liquor-store` haben
kein `test`-Skript, `secure-ui-test` gibt nur einen Hinweis aus, `poc-hardened` ist per Filter
ausgenommen.

Die drei laut README auf npm veröffentlichten Pakete (`shared-types`, `shared-crypto`,
`revocation-statuslist`) sind alle genutzt und von keinem Vorschlag betroffen.

### Genutzt (bleiben)

| Paket                   | Zeilen Code | Tests in `pnpm test` | Direkt importiert von (Quellcode)                                                                                                                                                                                                                                                          |
| ----------------------- | ----------: | -------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `shared-crypto`         |        5855 |                  312 | `audit-log`, `benchmarks`, `issuer-mock`, `oid4vp`, `oid4vp-verifier`, `poc-hardened`, `policy-engine`, `secure-memory`, `secure-storage`, `verifier-backend`, `verifier-sdk`, `wallet-core`, `wallet-pwa`                                                                                 |
| `policy-engine`         |        4015 |                  325 | `consent-ui`, `mcp-server`, `wallet-core`, `wallet-pwa`                                                                                                                                                                                                                                    |
| `mdoc`                  |        2644 |                  189 | `issuer-mock`, `oid4vp-verifier`, `wallet-pwa`                                                                                                                                                                                                                                             |
| `shared-types`          |        2624 |                   90 | `anchor-service`, `audit-log`, `connect`, `data-flow`, `issuer-mock`, `mcp-server`, `oid4vp`, `oid4vp-verifier`, `phase0-security`, `policy-engine`, `predicates`, `secure-storage`, `shared-crypto`, `verifier-backend`, `verifier-frontend`, `verifier-sdk`, `wallet-core`, `wallet-pwa` |
| `oid4vp`                |        2093 |                   94 | `connect`, `oid4vp-verifier`, `verifier-backend`, `wallet-pwa`                                                                                                                                                                                                                             |
| `audit-log`             |        1309 |                   30 | `benchmarks`, `wallet-core`, `wallet-pwa`                                                                                                                                                                                                                                                  |
| `connect`               |        1177 |                   66 | `verifier-backend`                                                                                                                                                                                                                                                                         |
| `predicates`            |         949 |                   90 | `policy-engine`, `verifier-backend`, `verifier-sdk`, `wallet-pwa`                                                                                                                                                                                                                          |
| `verifier-sdk`          |         901 |                   60 | `verifier-backend`, `verifier-demo-root`                                                                                                                                                                                                                                                   |
| `wallet-core`           |         660 |                   52 | `wallet-pwa`                                                                                                                                                                                                                                                                               |
| `revocation-statuslist` |         651 |                   26 | `shared-crypto`                                                                                                                                                                                                                                                                            |
| `data-flow`             |         438 |                   69 | `wallet-pwa`                                                                                                                                                                                                                                                                               |
| `secure-storage`        |         345 |                    9 | `wallet-core`, `wallet-pwa`                                                                                                                                                                                                                                                                |
| `layer-resolver`        |         281 |                   24 | `data-flow`, `demo-liquor-store`, `policy-engine`, `wallet-pwa`                                                                                                                                                                                                                            |

### Von keiner Anwendung genutzt

| Paket                  | Zeilen Code | Tests in `pnpm test` | Importiert von                                                                    | Vorschlag         | Begründung                                                                                                                                                                                                     | Entscheidung Owner |
| ---------------------- | ----------: | -------------------: | --------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| `evidence`             |         281 |                   24 | niemand                                                                           | behalten          | Eigener CI-Job (`.github/workflows/ci.yml`, Evidence-Runner und Typecheck).                                                                                                                                    |                    |
| `mock-issuer`          |         221 |                   14 | `demo-liquor-store`, `integration-tests` (nur Tests), `policy-engine` (nur Tests) | behalten          | Test-Fixture für `policy-engine` und `integration-tests`.                                                                                                                                                      |                    |
| `integration-tests`    |           0 |                   54 | niemand                                                                           | behalten          | Testet den Kern paketübergreifend. Importiert auch `eid-issuer-connector` und `webauthn-verifier`; deren Tests müssten bei einer Archivierung mitziehen.                                                       |                    |
| `eid-issuer-connector` |         627 |                   21 | `integration-tests` (nur Tests)                                                   | Owner entscheidet | Nur von `integration-tests` importiert.                                                                                                                                                                        |                    |
| `discrete-core`        |         626 |                   45 | niemand                                                                           | Owner entscheidet | Kein Importeur. #198 will es in Wallet und Policy-Engine einbauen: einbauen oder archivieren.                                                                                                                  |                    |
| `mcp-server`           |         579 |                   11 | niemand                                                                           | Owner entscheidet | Eigener Einstiegspunkt (`bin`) für Agenten; gehört nicht zum Altersnachweis-Flow.                                                                                                                              |                    |
| `oid4vp-verifier`      |         543 |                   63 | niemand                                                                           | Owner entscheidet | Verifier-Seite von OID4VP. `verifier-backend` importiert es nicht (nutzt `verifier-sdk`, `connect`, `oid4vp`): einbauen oder archivieren.                                                                      |                    |
| `webauthn-verifier`    |         456 |                   19 | `integration-tests` (nur Tests)                                                   | Owner entscheidet | Nur von `integration-tests` importiert.                                                                                                                                                                        |                    |
| `poc-hardened`         |        4864 |                keine | niemand                                                                           | archivieren       | Größter Einzelposten. Aus `build`, `lint` und `test` ausgenommen; die eigene README nennt es „Reference / NOT production“ und begründet das Behalten. Vorschlag: als Tag/Branch erhalten statt im Arbeitsbaum. |                    |
| `phase0-security`      |        1998 |                  149 | niemand                                                                           | archivieren       | Kein Importeur. #243 nennt doppelte Implementierungen und Fail-open-Demo-Pfade.                                                                                                                                |                    |
| `consent-ui`           |         966 |                   23 | niemand                                                                           | archivieren       | Kein Importeur. Die Wallet hat eigene Consent-Komponenten (`ConsentModal`, `ConsentManagerPanel`).                                                                                                             |                    |
| `anchor-service`       |         444 |                   12 | niemand                                                                           | archivieren       | Kein Importeur.                                                                                                                                                                                                |                    |
| `benchmarks`           |         296 |                keine | niemand                                                                           | archivieren       | Zwei Benchmark-Skripte, kein `test`-Skript.                                                                                                                                                                    |                    |
| `oid4vci`              |         257 |                   35 | niemand                                                                           | archivieren       | Kein Importeur. Die Wallet ruft Credentials über einen eigenen Pfad ab (`WalletService.fetchAndStoreSdJwtVc`).                                                                                                 |                    |
| `secure-memory`        |         181 |                    4 | niemand                                                                           | archivieren       | Kein Importeur im Quellcode.                                                                                                                                                                                   |                    |
| `demo-liquor-store`    |         154 |                keine | niemand                                                                           | archivieren       | Konsolen-Demo ohne `test`-Skript; die Demo existiert als App.                                                                                                                                                  |                    |
| `secure-ui-test`       |          44 |                keine | niemand                                                                           | archivieren       | Kein Importeur. Das `test`-Skript gibt nur einen Hinweis aus; `test:e2e` läuft nicht in `pnpm test`.                                                                                                           |                    |

## Was die Paket-Messung nicht zeigt

- Sie misst statische Importe. Ein genutztes Paket kann ungenutzte Module enthalten; das ist
  hier nicht untersucht.
- Kein automatischer Test startet die Dienste zusammen im Browser. Zwei Fehler im Demo-Start
  blieben deshalb bei grünem Testlauf unbemerkt (Behebung liegt in PR #265 vor, der am
  2026-11-13 noch nicht gemergt ist):
  die HTTPS-Origin der Wallet fehlte in der CORS-Liste des Verifiers, und Verifier-Links
  landeten auf der Landingpage statt in der Wallet.

## Doku-Ordner

Gemessen: Markdown- und Textdateien je Ordner, Verweise aus den vier Leitdateien
(`docs/DOCS_CANON.md`, `STATE.md`, `docs/BACKLOG.md`, `README.md`) auf den Ordnerpfad, und das
Datum der letzten Änderung. Der Klon reicht bis `a327ec6` (2026-07-14) zurück; dieses Datum
bedeutet deshalb „seit mindestens 2026-07-14 unverändert“.

### Vorschlag „archivieren“: keine Leitdatei verweist darauf

| Ordner                     | Dateien | Zeilen | Letzte Änderung | Hinweis für das Verschieben                                                                                                                                       | Entscheidung Owner |
| -------------------------- | ------: | -----: | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| `docs/vision/`             |      27 |  2.779 | ≤ 2026-07-14    |                                                                                                                                                                   |                    |
| `docs/b2b-use-cases/`      |       9 |  1.347 | ≤ 2026-07-14    |                                                                                                                                                                   |                    |
| `docs/context/`            |       7 |  1.111 | ≤ 2026-07-14    | Enthält zwei Chat-Mitschnitte (`VON_CGPT.txt`, `VON_CLAUDE.txt`). Kein Verweis über den Ordnerpfad; `docs/specs/` und `docs/00-welt/` nennen einzelne Dateinamen. |                    |
| `docs/modules/`            |       2 |    408 | ≤ 2026-07-14    | Verweise aus `docs/vision/` und `docs/b2b-use-cases/`; gemeinsam verschieben.                                                                                     |                    |
| `docs/01-grundversorgung/` |       1 |     84 | ≤ 2026-07-14    | Verweise aus `docs/specs/` und `docs/00-welt/`.                                                                                                                   |                    |
| `docs/ux/`                 |       1 |     81 | ≤ 2026-07-14    | Keine eingehenden Verweise.                                                                                                                                       |                    |
| `docs/architecture/`       |       1 |     54 | ≤ 2026-07-14    | Ein ADR (ADR-013, TEE); gehört eher zu `docs/03-architecture/`.                                                                                                   |                    |
| `docs/policies/`           |       2 |     44 | ≤ 2026-07-14    | Keine eingehenden Verweise.                                                                                                                                       |                    |
| `docs/session-reports/`    |       1 |     37 | ≤ 2026-07-14    | Verweis aus `docs/SESSION_HISTORY.md`.                                                                                                                            |                    |
| `docs/superpowers/`        |      14 |  3.670 | 2026-10-27      | Pläne und Entwürfe zu bereits gemergten PRs. `docs/BACKLOG.md` und ein Code-Kommentar in `shared-types` verweisen auf eine Datei.                                 |                    |

Summe: 65 Dateien, 9.615 Zeilen.

### Owner entscheidet: nur am Rand verankert

| Ordner               | Dateien | Zeilen | Letzte Änderung | Verweise aus Leitdateien                                                                                                                                         | Entscheidung Owner |
| -------------------- | ------: | -----: | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| `docs/00-welt/`      |       8 |  1.195 | ≤ 2026-07-14    | `BACKLOG.md`                                                                                                                                                     |                    |
| `docs/_core/`        |      11 |    929 | 2026-10-03      | `STATE.md`                                                                                                                                                       |                    |
| `docs/presentation/` |       5 |    588 | 2026-10-15      | `README.md`                                                                                                                                                      |                    |
| `docs/04-legal/`     |       2 |    109 | ≤ 2026-07-14    | `BACKLOG.md`; siehe auch #235                                                                                                                                    |                    |
| `docs/specs/`        |     114 |  5.601 | ≤ 2026-07-14    | `DOCS_CANON.md` nennt `SPECS_STATUS_INDEX.md` als Einstieg. Vorschlag: Index behalten und anhand seiner Statusspalte entscheiden, welche Specs ins Archiv gehen. |                    |

### Bleiben: von `DOCS_CANON.md` als Quelle oder Navigation benannt

`docs/03-architecture/` (22 Dateien), `docs/compliance/` (18), `docs/tasks/` (14),
`docs/05-business/` (18), `docs/eudi/` (1), `docs/protocol/` (1) sowie die Leitdateien im
Ordner `docs/`.

### Einzeldateien und Archiv-Orte

| Pfad                            | Befund                                                                                              | Vorschlag                                                       | Entscheidung Owner |
| ------------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------ |
| `archive/` und `docs/archive/`  | Zwei Archiv-Orte (34 und 9 Dateien). `archive/git-bundles/` belegt 5,3 MB.                          | Einen Ort festlegen; künftige Archivierungen gehen nur dorthin. |                    |
| `SPRINT_PLAN.md`                | 516 Zeilen, seit mindestens 2026-07-14 unverändert, 6 Dateien verweisen darauf.                     | archivieren                                                     |                    |
| `REFACTORING_ROADMAP.md` (Root) | 7 Zeilen, nur Weiterleitung auf `docs/REFACTORING_ROADMAP.md`.                                      | Verweise umstellen, dann entfernen                              |                    |
| `GEMINI.md`                     | Leer (0 Zeilen).                                                                                    | füllen oder entfernen                                           |                    |
| `test_wallet_ui.cjs`            | 79 Zeilen, keine Verweise; ruft `http://localhost:5175/?demo=wallet` auf, den Port der Verifier-UI. | entfernen                                                       |                    |

## Methode

- **Pakete:** alle versionierten `.ts`-, `.tsx`-, `.js`-, `.mjs`- und `.cjs`-Dateien unter `src/`
  werden nach Importen von `@askmi/<paket>` (auch Unterpfade, `require` und dynamisches
  `import()`) sowie nach relativen Pfaden auf `packages/<paket>/` durchsucht. Eine Datei gilt
  als Testdatei, wenn ihr Pfad `__tests__`, `.test.`, `.spec.`, `/test/`, `/tests/` oder `/e2e/`
  enthält. Die Erreichbarkeit ist die transitive Hülle der Quellcode-Importe ab den vier
  Anwendungen.
- **Gegenprobe pro Paket:** `git grep -l "@askmi/<paket>" -- src`
- **Tests:** Zeilen `Tests  N passed` je Paket aus der Ausgabe von `pnpm test`.
- **Doku-Ordner:** `git ls-files docs/<ordner>`, Verweise per
  `grep -E "(docs/)?<ordner>/"` in den vier Leitdateien, Datum per
  `git log -1 --format=%ad --date=short -- docs/<ordner>`.

## Nächste Schritte

1. Owner trägt pro Zeile eine Entscheidung ein (hier oder im PR).
2. Je Entscheidung ein PR: verschieben, Verweise anpassen, `DOCS_CANON.md` nachziehen.
3. Für archivierte Pakete vorher festlegen, ob sie als Ordner im Archiv oder nur als Git-Tag
   erhalten bleiben.
