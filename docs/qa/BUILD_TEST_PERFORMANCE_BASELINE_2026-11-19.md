# Build/Test-Laufzeit — Baselinemessung

**Datum:** 2026-11-19
**Revision:** `551a09d` (Branch `chore/session-22-history`; Working Tree nicht clean — u. a. `package.json`, `src/apps/verifier-demo/frontend/src/App.tsx`, `src/apps/issuer-mock/src/index.ts` lokal verändert, nicht Teil dieser Messergebnisse)
**Umgebung:** Windows 11, 12 Kerne, Node v24.16.0, pnpm 9.15.9, Turbo lokal mit Warm-Cache (`node_modules/.cache/turbo`)
**Bewertungsstatus:** Beobachtung, kein Sicherheits-/Performance-PASS. Alle Messungen lokal unter Windows; CI läuft auf ubuntu-latest (Node 22) und ist hier NICHT gemessen.

## Fragestellung

Warum wirken `pnpm build` / `pnpm test` lang? Es existierte keine dokumentierte Grundmessung (BACKLOG/STATE/SESSION_HISTORY ohne Treffer zu Laufzeiten).

## Messprotokoll (alle Runs: exit 0, Tests bestanden)

| Run | Turbo-Zeit | real (time) | Aufgaben | aus Cache |
|---|---|---|---|---|
| `pnpm build` (warm) | 5.73 s | 7.08 s | 31 | 30 cached |
| `pnpm test` (warm) | 3.975 s | 5.33 s | 49 | 48 cached |
| `pnpm exec turbo run test --force` (kalt, inkl. `^build`) | 3m 57.3 s | 3m 58.6 s | 50 | 0 cached |

**Kernaussage:** Im Warm-Zustand sind Build und Tests in Sekunden fertig. Die erlebte Dauer entsteht im Kalt-/Invalidierungszustand: lokal nach Änderungen an tief im Graph liegenden Packages, in CI bei jedem Run (kein Turbo-Cache dort, nur pnpm-Store-Caching).

## Suiten-Dauern aus dem Kalt-Run (Wall-Clock pro Package, Top 12; Worker parallel, Summe ~505 s bei 3m58s Wall-Clock)

| Paket | Dauer | Aufschlüsselung (vitest, parallel aggregiert) |
|---|---|---|
| @askmi/wallet-pwa | 120.5 s | environment 67.9 s (jsdom), setup 13.6 s, import 11.3 s, transform 3.3 s, Tests 17.1 s |
| @askmi/evidence | 87.0 s | Tests 83.7 s (echte Testarbeit, Node-Env) |
| @askmi/consent-ui | 29.1 s | import 179.3 s, Tests 64.4 s, transform 20.3 s (aggregiert über Worker) |
| @askmi/policy-engine | 27.1 s | import 73.9 s, transform 35.3 s, Tests 10.0 s |
| @askmi/phase0-security | 23.3 s | — |
| @askmi/issuer-mock | 19.8 s | — |
| @askmi/shared-crypto | 18.5 s | Tests 57.9 s, import 21.9 s, transform 8.7 s (PQC-Krypto-Arbeit real, aber nicht dominierend) |
| @askmi/verifier-sdk | 13.9 s | — |
| @askmi/mcp-server | 13.6 s | — |
| @askmi/connect | 12.9 s | — |
| @askmi/integration-tests | 12.7 s | — |
| @askmi/audit-log | 12.4 s | — |

## Ursachenanalyse (belegt)

1. **wallet-pwa/jsdom bestätigt als Einzeltreiber Nr. 1:** 120 s Suite-Dauer, davon 68 s allein Environment-Aufbau (jsdom-Boots), nur 17 s echte Testausführung. Vitest-Config: `environment: 'jsdom'` mit Default-Isolation, Aliasse auf `src/` von 9 Workspace-Packages — jede Änderung an shared-crypto/policy-engine/mdoc/etc. invalidiert diese Suite mit.
2. **evidence bestätigt als Einzeltreiber Nr. 2, aber andere Ursache:** 87 s, davon 84 s echte Tests — reale Testarbeit, kein Boot-Overhead. Optimierungshebel hier wäre Testinhalt/Parallelität, nicht Environment.
3. **PQC/Shared-Crypto-Hypothese partially bestätigt:** 58 s echte Krypto-Testarbeit, aber nur Rang 7 der Einzeldauern — nicht die Hauptursache der empfundenen Dauer.
4. **Import-/Transform-Overhead bei policy-engine/consent-ui:** aggregierte Importzeiten (74 s bzw. 179 s über parallele Worker) deutlich über der reinen Testzeit — Modulgraph-Analyse wäre ein eigener Befund, hier nicht untersucht.
5. **Cache-Invalidierung:** `turbo.json` definiert keine `inputs` — jede Dateiänderung in einem Package (inkl. README) invalidiert dessen Build+Test-Cache und alle Downstream-Einträge.
6. **CI-Kaltlauf:** `ci.yml` cached nur den pnpm-Store; Turbo-Start pro Run kalt, `build`→`test`→`lint` sequenziell, und der `layer-validation`-Job baut erneut komplett (`pnpm build`).

## Grenzen dieser Messung (was sie NICHT aussagt)

- Keine Messwerte von GitHub-Actions-Läufen (CI-Dauer unbekannt; ubuntu-Messung fehlt).
- Kalt-Run lokal einmalig; Varianz zwischen Runs nicht bestimmt.
- lokaler Node 24 vs. CI Node 22 — versionsbedingte Differenzen nicht gemessen.
- Ursache der hohen evidence-Testdauer (Testinhalt) nicht im Detail analysiert.
- Build-Ausgabe enthielt eine Pfadreferenz auf einen `wt-fix238`-Worktree in shared-crypto-Platform-Warnung (Vite externalize-Hinweis) — unbeachtet, nicht geklärt.

## Abgeleitete Follow-ups (Vorschläge, NICHT umgesetzt)

1. turbo `inputs` je Task definieren (Cache-Invalidierung einschränken).
2. CI: Turbo-Cache (actions/cache für `.turbo`) oder Remote-Cache (benötigt Owner-Entscheidung + Secrets).
3. wallet-pwa jsdom-Boot-Kosten senken (z. B. `isolate: false` / weniger eigene Environments), evidenzbasiert gegen diese Baseline messen.
4. evidence-Tests auf Teilbarkeit/Parallelität prüfen.
5. Dev-Workflow: `turbo test --filter=...[origin/master]` als Standard für lokale Iteration.
