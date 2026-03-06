# ANTIGRAVITY_TASKS.md — Session: UX Polish & User Flow

**Datum:** 2026-03-06
**Branch:** `ux-polish` (NEU — von `master` abzweigen: `git checkout -b ux-polish`)
**Scope:** NUR `src/apps/wallet-pwa/` — keine Engine/Crypto Pakete anfassen!
**Vorgabe:** Autonome Abarbeitung. Bei Blocker → `BLOCKED.md` schreiben.

⚠️ **WICHTIG:** Claude Code arbeitet parallel auf `master` an Engine/Crypto.
Du darfst NUR Dateien in `src/apps/wallet-pwa/` ändern. Keine Änderungen an:
- `src/packages/*` (tabu!)
- `shared-types`, `shared-crypto`, `policy-engine` (tabu!)
- `STATE.md`, `BACKLOG.md` (tabu — Claude updatet die)

---

## Kontext

Die Wallet-PWA ist eine Demo-App für eine Uni-Präsentation. Sie funktioniert, aber die UX ist "Entwickler-UI" — inline styles, kein Feedback, kein Flow-Gefühl. Ziel: **Stakeholder sollen "Wow" sagen**, nicht "was muss ich hier klicken?"

Aktuelle Struktur:
- `App.tsx` (797 Zeilen) — Monolith, alles in einer Komponente
- `ConsentModal.tsx` (373 Z.) — Consent + WebAuthn, gut strukturiert
- `GuidedDemoMode.tsx` (297 Z.) — Bottom-Sheet Tutorial
- `PolicyEditor.tsx` (401 Z.) — Rule Editor
- `AuditReportPanel.tsx` (264 Z.) — Compliance Dashboard
- `PrivacyAuditModal.tsx` (226 Z.) — Transparency Layer
- `SecureZone.tsx` (131 Z.) — Wrapper
- `App.css` — Minimal, meiste Styles sind inline

---

## UX-01: Inline Styles → CSS Modules / Klassen

**Problem:** ~90% der Styles sind inline in JSX. Unlesbar, nicht wartbar, keine Hover/Focus States möglich.
**Was:**
- [ ] CSS-Datei(en) erstellen für wiederkehrende Patterns (Cards, Buttons, Badges, Grid)
- [ ] Inline Styles in App.tsx durch Klassen ersetzen
- [ ] Hover-Effects für alle interaktiven Elemente
- [ ] Focus-visible für Accessibility
- [ ] Transitions: `transition: all 0.2s ease` auf Buttons und Cards

**Nicht:** Kein CSS-in-JS Library, kein Tailwind — plain CSS reicht.

---

## UX-02: Status-Feedback & Transitions

**Problem:** Zustandswechsel (IDLE → EVALUATING → PROVING → SHREDDED) sind abrupt. Kein visuelles Feedback.
**Was:**
- [ ] Loading Spinner oder Pulse-Animation während EVALUATING
- [ ] Fortschritts-Indikator während PROVING (z.B. animierter Balken)
- [ ] Smooth Transitions zwischen Zuständen (CSS transitions, nicht harte Swaps)
- [ ] SHREDDED-State: kurze "Shredding"-Animation (Partikel, Fade, Dissolve — was auch immer gut aussieht)
- [ ] DENIED-State: Shake-Animation auf dem Button (subtil)
- [ ] Erfolgs-Feedback: kurzer grüner Flash oder Checkmark-Animation bei ALLOW

---

## UX-03: Credential Card Redesign

**Problem:** Die Credential-Anzeige oben ist ein statisches Div mit hartcodierten Werten. Sieht nicht nach "Wallet" aus.
**Was:**
- [ ] Card-Design das an eine echte Karte/Ausweis erinnert (abgerundete Ecken, Gradient, Shadow)
- [ ] Subtle Hologramm/Shimmer-Effekt (CSS only — `background: linear-gradient` Animation)
- [ ] Credential-Type Icon (🪪 für GovID, 🏥 für Hospital)
- [ ] Trust-Badge besser positionieren (oben rechts, wie ein Siegel)
- [ ] Wenn mehrere Credentials: horizontal scrollbar oder Stack mit Peek

---

## UX-04: Button Grid — Klarere Hierarchie

**Problem:** "Advanced Feature Demos" Grid hat 8 Buttons, alle gleich groß, keine klare Hierarchie.
**Was:**
- [ ] Primäre Szenarien (Liquor, Doctor, ER, Pharmacy) prominenter — größer, oben
- [ ] Sekundäre (WebAuthn, Recovery, Research, Cross-Border) kleiner, als "More Demos" collapsible
- [ ] Button-Labels kürzer und klarer (z.B. "🍺 Age Check" statt "🍺 Liquor Store")
- [ ] Disabled-State besser visualisieren (nicht nur opacity)
- [ ] Ripple-Effect oder Scale-Down beim Klicken (`transform: scale(0.97)`)

---

## UX-05: Audit Log — Besser lesbar

**Problem:** Monospace-Log ist funktional aber trocken. Für eine Demo sollte es "leben".
**Was:**
- [ ] Neue Log-Einträge sliden rein (CSS animation: slideIn)
- [ ] Farbige Icons statt Text-Prefixes (✅ grün, ⚠️ gelb, ❌ rot — schon da, aber größer/prominenter)
- [ ] Auto-Scroll zum neuesten Eintrag
- [ ] Max-Height mit Scroll statt unbegrenztem Wachstum
- [ ] "Copy Log" Button (klein, oben rechts)

---

## UX-06: ConsentModal — Flow Polish

**Problem:** ConsentModal funktioniert gut, aber der Flow könnte flüssiger sein.
**Was:**
- [ ] Entry-Animation: Modal gleitet von unten rein (mobile Pattern)
- [ ] Claim-Liste: Chips statt Textliste (grüne Chips = freigegeben, rote = geblockt)
- [ ] Risk-Level prominenter anzeigen (farbiger Banner oben im Modal)
- [ ] WebAuthn-Button: Pulsing-Animation wenn Biometrie erforderlich (Aufmerksamkeit lenken)
- [ ] Timer-Visualisierung wenn `timeoutMinutes` gesetzt (Countdown-Ring)
- [ ] Reject-Button weniger prominent als Approve (kein roter Button, eher Text-Link)

---

## UX-07: GuidedDemoMode — Storytelling

**Problem:** Bottom-Sheet ist informativ aber statisch. Für die Präsentation brauchen wir Flow.
**Was:**
- [ ] Step-Indicator (Dots oder Progress Bar: 1/4, 2/4...)
- [ ] Transition zwischen Steps (Slide left/right)
- [ ] "What the Verifier sees" als visueller Diff (grün = sichtbar, durchgestrichen rot = geblockt)
- [ ] Nach Szenario-Ausführung: Ergebnis-Summary im Sheet anzeigen (nicht nur im Log)
- [ ] Konfetti oder Checkmark-Animation nach erfolgreichem Step

---

## UX-08: Mobile-First Polish

**Problem:** Die App soll auf einem Handy-Screen bei der Präsentation gut aussehen.
**Was:**
- [ ] Viewport meta tag checken (`<meta name="viewport" content="width=device-width, initial-scale=1">`)
- [ ] Touch-Targets: mindestens 44x44px für alle Buttons
- [ ] Safe Area Insets (für Notch-Phones): `env(safe-area-inset-*)`
- [ ] Bottom-Sheet (GuidedDemo) darf nicht den Hauptbutton verdecken
- [ ] Landscape-Modus: Zweispaltiges Layout wenn genug Platz

---

## Reihenfolge

1. **UX-01** (CSS Cleanup) — Fundament für alles andere
2. **UX-02** (Transitions) — größter visueller Impact
3. **UX-03** (Credential Card) — erster Blickfang
4. **UX-06** (ConsentModal) — Kern der Demo
5. **UX-07** (GuidedDemo) — Präsentations-Flow
6. **UX-04 + UX-05** (Buttons + Log)
7. **UX-08** (Mobile) — Final Polish

## Regeln

- `git checkout -b ux-polish` bevor du anfängst!
- Commits nach jedem Task
- Keine neuen npm Dependencies (CSS only!)
- Bestehende Funktionalität NICHT brechen — nur visuell verbessern
- `npx turbo run build --filter=wallet-pwa` muss grün bleiben
- TypeScript strict, keine Type-Fehler einführen

---

*Erstellt von Claw 🦀 — 2026-03-06*
