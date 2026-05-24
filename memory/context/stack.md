# Tech Stack & Kontext

## Sprache & Tooling

- **TypeScript** — strict mode, Monorepo via pnpm workspaces
- **pnpm** + **Turbo v1** (`pipeline` in turbo.json, NICHT `tasks`)
- **Vitest** — Testframework. `node` env für Packages, `jsdom` env für wallet-pwa
- **ESLint** + **Prettier** (single quotes, 2-space, trailing commas es5, 100 chars)
- **Node 22**, **pnpm 9** in CI

## Aktueller Architektur-Handoff

- Stand: 2026-05-25.
- Architekturpruefprozess v2: `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md`.
- Coding-Agent-Uebergabe: `docs/03-architecture/CODING_AGENT_HANDOFF_2026-05-25.md`.
- Review-Regel: Unklarer Architekturstatus ist `UNKNOWN => FAIL`.
- Aktueller Workspace-Scan: 27 Package-Workspaces unter `src/packages/`.
- Apps: fachlich 3 Apps; workspace-technisch 5 App-Projekte wegen `verifier-demo` Root/Backend/Frontend.
- Vor Weiterarbeit immer zuerst `git status --short --branch` lesen, weil mehrere Branch-/ADR-/Code-Spuren zusammengefuehrt wurden.

## CI/CD

- **GitHub Actions** `.github/workflows/ci.yml`: build → test → lint
- Separate `ci-security.yml`: `pnpm audit` Security-Job
- Branch: `master` (Default) — CI-Trigger muss auf `master` zeigen
- **Layer Validation Job**: tests policy-engine E2E scenario

## Test-Besonderheiten

- wallet-pwa: braucht `fake-indexeddb/auto` + `document.elementFromPoint` stub + SecureStorage-Mocks
- secure-storage: `fake-indexeddb/auto` via setup file
- `MITCH_TEST_MODE=1` für test-mode-spezifisches Verhalten

## Krypto-Stack

- **@noble/curves** — Ed25519, P-256, brainpool
- **@noble/post-quantum** — ML-DSA, ML-KEM
- **AES-256-GCM** — Encryption at rest
- **Web Crypto API** (SubtleCrypto) — Browser-native, async
- **CBOR** — für mdoc (ISO 18013-5)

## Ports (lokale Entwicklung)

| App | Port |
|-----|------|
| wallet-pwa | 5173 (oder 5174) |
| verifier-demo | 3004 |
| issuer-mock | 3005 |

## Schlüsseldateien für Navigation

| Datei | Zweck |
|-------|-------|
| `STATE.md` | Aktueller Betriebszustand |
| `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md` | Neuer Standardprozess fuer Architekturpruefung |
| `docs/03-architecture/CODING_AGENT_HANDOFF_2026-05-25.md` | Einstiegspunkt fuer den Coding Agent |
| `docs/BACKLOG.md` | Autoritatives Task-Tracking |
| `docs/SESSION_HISTORY.md` | Vollständige Session-Historie |
| `CLAUDE.md` / `AGENTS.md` | KI-Arbeitsanweisungen |
| `CLAUDE_TASKS.md` | Session-spezifische Task-Listen (historisch) |
| `SPRINT_PLAN.md` | Audit-Findings März 2026 |
| `TASKS.md` | Produktivitäts-Tracker (dieser Workflow) |
| `dashboard.html` | Produktivitäts-Dashboard |
