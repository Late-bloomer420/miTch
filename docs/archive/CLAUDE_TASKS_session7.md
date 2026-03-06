# CLAUDE_TASKS.md — Session 7: ESLint Cleanup + GitHub Pages + Demo Polish

**Datum:** 2026-03-06
**Vorgabe:** Autonome Abarbeitung, keine Rückfragen. Bei Blocker → `BLOCKED.md` schreiben.
**Branch:** `master` (direkt committen)
**Commit-Stil:** `feat/test/fix/docs(package): Kurzbeschreibung`
**Tests:** `npx turbo run test` muss am Ende grün sein.
**Arbeitsverzeichnis:** `/mnt/d/Mensch/miTch`

---

## Aktueller Stand

- 38/38 turbo tasks, Tests grün, 0 lint errors
- Session 6 erledigt: D-01 (E2E Tests), D-02 (Demo Script), B-01/B-02 (Backlog/State), P-01/P-02 (Presentation)
- ESLint Warnings: ~260 (Block H aus Session 6 noch offen)
- `standalone.html` ist die teilbare Demo (kein Server nötig)

---

## Block H — ESLint Warnings Cleanup 🔴 (Übertrag aus Session 6)

### H-01b: ESLint Warnings eliminieren
**Was:**
- [ ] `no-unused-vars`: Unbenutzte Variablen entfernen oder mit `_` prefixen
- [ ] `no-explicit-any`: Durch spezifische Types ersetzen wo möglich, `unknown` wo nötig
- [ ] Package für Package durchgehen (shared-types → shared-crypto → policy-engine → ... → wallet-pwa)
- [ ] KEINE funktionalen Änderungen — nur Type-Fixes und Dead Code Removal
- [ ] Nach jedem Package: `npx turbo run test` muss grün bleiben

**Acceptance:** `npx eslint src/` zeigt 0 warnings (oder < 10 unvermeidbare).

---

## Block G — GitHub Pages Deployment 🔴

### G-01: standalone.html als GitHub Pages deployen
**Was:**
- [ ] `.github/workflows/pages.yml` erstellen — deployt `src/packages/poc-hardened/src/poc-web/standalone.html` als `index.html`
- [ ] Workflow: on push to master, nimmt nur die eine HTML-Datei
- [ ] KEIN Build-Step nötig — Datei ist self-contained
- [ ] Teste dass der Pfad stimmt (GitHub Pages root = `index.html`)
- [ ] Optional: `404.html` → redirect zu `index.html`

**Acceptance:** Nach Push ist die Demo unter `https://late-bloomer420.github.io/miTch/` erreichbar.

### G-02: OpenGraph / Social Meta Tags
**Was:**
- [ ] `<meta property="og:title">`, `og:description`, `og:image` in standalone.html
- [ ] `<meta name="twitter:card">` für Link-Previews
- [ ] Titel: "miTch — The Forgetting Layer"
- [ ] Description: "Privacy Middleware for National Identity Wallets. Interactive Demo."

**Acceptance:** Link-Preview in Telegram/WhatsApp zeigt Titel + Beschreibung.

---

## Block R — Repo Cleanup 🟡

### R-01: README.md aufräumen
**Was:**
- [ ] Kurze Projektbeschreibung oben (max 5 Zeilen)
- [ ] Badges: Tests passing, License, GDPR compliant
- [ ] Quick Start: `pnpm install && pnpm dev`
- [ ] Link zur Live Demo (GitHub Pages URL)
- [ ] Link zu DPIA, Architecture Docs, Presentation Outline
- [ ] Alte/veraltete Sections entfernen

### R-02: Stale Files entfernen
- [ ] `CLAUDE_TASKS.md` → nach `docs/archive/` verschieben (nicht auf GitHub Pages sichtbar)
- [ ] `ANTIGRAVITY_TASKS.md` → nach `docs/archive/`
- [ ] `BLOCKED.md` löschen falls leer
- [ ] Prüfen ob andere temp files rumliegen

**Acceptance:** Repo sieht clean aus für externe Betrachter.

---

## Reihenfolge
1. H-01b (ESLint — aufräumen bevor neue Leute den Code sehen)
2. G-01 + G-02 (GitHub Pages — Demo muss teilbar sein)
3. R-01 + R-02 (Repo polish)
4. Final: `npx turbo run test` grün, git push
