# AskMI — Master Backlog

> **Rolle:** Autoritatives Task-Tracking — was ist erledigt, was ist offen, was ist geplant.
> Für operativen Health-Snapshot (Tests, Lint, Demo) siehe [`../STATE.md`](../STATE.md).

**Stand:** 2026-06-07 (Truth-Alignment: master bei `fb879cc`/PR #81; voller AskMI-Rebrand via PR #70 gemerged; Epic 2–5 Advisory-Arbeit (#71–#81) dokumentiert in `STATE.md` + Session 17; ältere Video-Gap-Tabellen teilweise durch Phase-1–Phase-4 + Epic-Arbeit überholt)
**Update 2026-06-10:** EPIC G-100 verfeinert — G-100.1/.2 auf EUDI-geformten Claim-Contract (Design-Doc + Branch `feature/g100-claim-contract`); EUDI-Interop-Gap als G-100.5 + Issue [#97](https://github.com/Late-bloomer420/miTch/issues/97) ehrlich getrackt; `verifier-browser`-Deprecation als G-100.6; widersprüchliche „G-100 ✅"-Altzeile (1.2) als nur-teilweise/History korrigiert.

**Update 2026-06-11:** EPIC G-100 P0-Block **geschlossen** — G-100.2 (Contract, PR #98), G-100.1 (asOf-Determinismus, PR #99), G-100.6 (verifier-browser archiviert + Import-Guard, PR #100) alle ✅ auf `master`. Neu: G-100.7 (flaky anti-oracle Timing-Test). Offen bleibt G-100.4 (Correlation IDs), G-100.5 (#97 EUDI-Interop/mdoc-AV+ZKP, deferred) und G-130.1 (Passkey-Onboarding als erzwungener Default, laufender Branch `feature/g130-passkey-default-onboarding`).

**Update 2026-06-20 (H-10 Truth-Alignment):** `master` steht jetzt bei `20478f0`/**PR #104** (war `fb879cc`/#81 in den Stand-Zeilen oben). Seither gemerged: G-100.7 (#102), **G-130.1 Passkey-Onboarding gelandet** (#103 + #104) → der ⏳-Eintrag in EPIC G-130 unten ist auf ✅ korrigiert. G-100.7 (#102) ✅. **Statuskonvention geklärt** (löst den scheinbaren Widerspruch): die `Phase 3 — Identity Ecosystem & UX ✅`-Zeilen sind die *groben Meilenstein-Rollups* (G-120/G-130/G-150 als Konzept gelandet); die `Video Gap Analysis`-EPIC-Tabellen (G-110.x … G-170.x) sind die *granulare Re-Skopierung* vom 2026-05-31 und werden einzeln getrackt — beide beschreiben dieselben Bereiche auf unterschiedlicher Granularität, kein Widerspruch. **Capsule-Sig-„Failures" gelöst** (Rebrand-AAD-Drift, kein Crypto-Bug) — Evidenz [`qa/CAPSULE_SIG_ROOTCAUSE_2026-06-18.md`](qa/CAPSULE_SIG_ROOTCAUSE_2026-06-18.md). Voller Suite-Lauf 2026-06-20: 46/46 Turbo-Test-Tasks grün. Noch offen/ehrlich: G-100.4, G-100.5/#97, U-10–U-13 (BBS+), G-110/G-120/G-140/G-150/G-160/G-170 (granular), S-10, Issue #95.

**Update 2026-07-04 (G-100.4 branch closure):** `feat/g100.4-correlation-ids` schließt den Correlation-ID-Pfad lokal: `shared-types` definiert `txn_*` IDs + Resolver, OID4VP-Verifier und `VerifierSDK` minten non-semantische IDs, OID4VP parsing/encoding erhält sie, `policy-engine` spiegelt sie in der `DecisionCapsule`, Wallet-Audit (`POLICY_EVALUATED`, `VP_GENERATED`, Proximity-`VP_SENT`) gruppiert über dieselbe ID, und `issuer-mock` spiegelt `x-correlation-id` auf `/credential` + `/credential/mdoc`. Validierung 2026-07-04: `pnpm run guard:rebrand`, `pnpm lint`, `pnpm test` → 46/46 Turbo-Tasks grün; zusätzlich gezielt `shared-types`, `oid4vp`, `oid4vp-verifier`, `verifier-sdk`, `policy-engine`, `wallet-pwa` Tests sowie Builds für `shared-types`, `oid4vp`, `oid4vp-verifier`, `issuer-mock`, `wallet-pwa`. Noch nicht auf `master` gemerged.

**Update 2026-06-21 (G-140 Layer-2 PR1 + Merges, superseded below):** master jetzt `1d0264d`/**PR #112**. Gemerged seit H-10: #110 (H-10 docs), #109 (EU-boundaries/Layer-2 Fundament 08/09 + Entsch. 1&2), #108 (dependabot), #106 (4-Fenster-Launcher konsolidiert), **#112 (G-140 Layer-2 PR1)**. PR1 = `WalletService.evaluateRequest()` loggt ein neutrales, PII-minimales `POLICY_EVALUATED`-Event auf JEDEM Verdict (requested_claims roh inkl. Over-Ask, authorized, denied = requested−authorized, verdict, reason_codes; neuer Typ `DisclosureDecisionMetadata`). Zu diesem Zeitpunkt war G-140.1 noch offen; die Folge-PRs #114/#115/#116 schließen die Kette im Update direkt darunter. Noch offen/PRs: #111 (dependabot vite), #105 (wallet public-preview, exposure — hold).

**Update 2026-06-21 (G-140 Layer-2 sequence closed):** master jetzt `c118f93`/**PR #116**. G-140.1 ist über die kleine PR-Kette **#112 → #114 → #115 → #116** gelandet: raw requested/authorized/denied auf jedem Verdict, DataFlow liest DENY + Over-Ask ehrlich, proximity mdoc ist sichtbar, und proximity mdoc wird vor Disclosure policy-geroutet. Demo-Regel `did:askmi:proximity-reader` erlaubt exakt `given_name` + `family_name`; Over-Ask wird nicht geteilt, DENY bleibt als sichtbare Layer-2-Transaktion erhalten. Validierung #116: wallet-pwa 162/162, data-flow 67/67, `pnpm test` 46/46 Turbo-Tasks, `pnpm build` 29/29, `guard:rebrand` grün. Noch offen/PRs: #111 (dependabot vite), #105 (wallet public-preview, exposure — hold).

**Update 2026-06-22:** #111 (dependabot `vite` 6.4.2→6.4.3, reine Dev-/Build-Abhängigkeit — nur `pnpm-lock.yaml` + 2 `package.json`, kein Runtime-Code) gemerged → master jetzt `1a86d62` (war `c118f93`/#116). Noch offen: **#105** (wallet public-preview, exposure — **hold**).

**Update 2026-06-24 (G-140 surfacing follow-up #119/#120):** master jetzt `e9bec3c`/**PR #120** (war `1a86d62`/#111). Die G-140 Sichtbarkeits-Kette ist mit dem Surfacing-Follow-up komplett: **#119** (Substrat — Sensitivität als reine Projektion von `layer-resolver` `0/1/2→low/medium/high`, unmapped→`unclassified`; `requested_claim_layers` auf jedem `POLICY_EVALUATED`; `DataFlowTransaction.claimSensitivity`; Enforcement **unangetastet** via separater `VISIBILITY_LAYER_MAP`-Superset, Guard-Test sichert `bloodGroup===WELT`) und **#120** (Display — neutrale Pro-Claim-Sensitivitäts-Badges in `DataFlowPanel`, Panel von Toggle zu **dauerhafter erstklassiger Sektion**). Validierung: `pnpm test` 46/46 Turbo grün, `guard:rebrand` grün. Ehrliches Side-Finding (damals getrackt, im Update 2026-06-25 geschlossen): der policy-engine Layer-Check **unterschützt** Demo-Health-Vokabular (`bloodGroup`/`medication`/`role` = WELT enforcement-seitig); die Visibility zeigt sie als `high`. **#105** bleibt **hold** (exposure). Scope-Check 2026-06-22: #105 ist auf *Scope/Stale*, nicht Code-Korrektheit blockiert (einziger Merge-Konflikt = diese Datei, narrativ). Drei Teile: A) Cloudflare-`trycloudflare.com`-Tunnel (wallet/issuer/verifier) + Download-Tooling = exposure-sensibel, widerspricht der Stable-Hosted-Env-Präferenz; B) issuer-mock CORS-Wildcard für `*.trycloudflare.com`; C) low-risk & nützlich = `DecisionCapsule.service_endpoint` + Verifier-Key-Fallback via `/did.json`. Empfehlung: gehalten lassen; bei Bedarf nur Teil C als kleine, saubere PR salvagen; A/B nur bei bewusster Hosted-Preview-Neuausrichtung.

**Update 2026-07-01 (S-11 Enforcement-Layer geschlossen):** S-11 ist im Arbeitsstand geschlossen und heute validiert. Die konkreten Health-/Professional-Claims (`bloodGroup`, `allergies`, `activeProblems`, `emergencyContacts`, `medication`, `dosageInstruction`, `refillsRemaining`, `role`, `licenseId`) sind jetzt im Enforcement-`LAYER_MAP` als `VULNERABLE` klassifiziert; die Visibility bleibt ein Superset fuer display-only Claims. Legitime Doctor/EHDS/Research/Pharmacy-Regeln deklarieren explizit `minimumLayer: VULNERABLE`, sodass Consent, Presence, Break-Glass, HDAB und Geo-Scope nicht durch fruehe `LAYER_VIOLATION`s kurzgeschlossen werden. Negative Regression: WELT/default-Verifier bekommen `bloodGroup` nicht, Layer-1-Verifier bekommen `licenseId` nicht. Validierung: `pnpm --filter @askmi/layer-resolver test`, `pnpm --filter @askmi/policy-engine test`, `pnpm --filter @askmi/integration-tests exec vitest run src/demo-scenarios.test.ts`, `pnpm test` (46/46 Turbo-Tasks) und `pnpm guard:rebrand` gruen.

**Update 2026-07-13 (Dead-Code-Sichtung — parked, nicht gelöscht):** Eine knip-Sichtung fand eine in sich geschlossene, aber **nirgends verdrahtete** Komponenten-Insel in `wallet-pwa`, die de facto die **schon getrackte** Visual-Rendering-Arbeit ist (E-45 / V-01–V-04) bzw. Proximity-UX (G-110). Kein `App.tsx`-Pfad importiert die Wurzeln. **Bewusst behalten** (TODO-Marker im Code, Backlog-Referenz), nicht entfernt: `components/SecureIframeRenderer.tsx` (V-02, sandboxed CSP-iframe), `components/CredentialRenderer.tsx` (V-01 renderMethod + V-03 svg-mustache + V-04 digestMultibase), `components/CredentialCard.tsx` (E-45 branded card), `components/ProximityView.tsx` + `services/ProximityService.ts` (G-110 / E-11 ISO-18013-5 Proximity-UI), `components/DocumentsTab.tsx` (Proof-of-Existence-Tab, `DocumentService` bleibt anderweitig genutzt). Deshalb bleiben auch die zugehörigen Deps `mustache`/`@types/mustache` (CredentialRenderer) und `qrcode.react` (ProximityView) deklariert. **Aufgeräumt:** ungenutzte `i18n/medical-terms.ts` in `utils/i18n.ts` konsolidiert (E-38/T-C3, war Dublette der `CLAIM_DICTIONARY`); ungenutzte `jose`-Dependency aus `verifier-demo/backend` und `@askmi/revocation-statuslist` entfernt. `@simplewebauthn/*` in `webauthn-verifier` bleibt bewusst deklariert (per ADR-009 für die künftige vollständige Signatur-Verifikation reserviert).

**Update 2026-07-13 (Fail-Closed für GDPR-Outward-Actions — 2 Bugs behoben):** Beim Prüfen einer ESLint-„unused proofToken"-Meldung fielen zwei echte Bugs in `WalletService` auf, die jetzt behoben + getestet sind. (1) **False-Success:** `requestDataErasure` (CIR 2024/2982 I9) und `reportRelyingParty` (Art. 7) gaben bedingungslos `success:true` zurück und schrieben Audit `status:'SENT'`/`REPORT_SENT`, **ohne** je etwas zu senden — der signierte `proofToken` wurde verworfen (Netzwerk-POST auskommentiert bzw. ganz fehlend). Jetzt: gemeinsamer `postSignedRequest()`-Helfer POSTet den signierten Token echt und **fail-closed** — Erfolg nur bei HTTP 2xx, sonst `success:false` + Audit `status:'FAILED'` (mit `delivery_error`/`http_status`); bei Erfolg wird `proof_token` in den unveränderlichen Audit-Trail geschrieben. Beide Methoden sind jetzt symmetrisch. (2) **signData Key-Name-Mismatch:** `signData()` las per Cast `auditLog.privateKey`/`publicKey`, während `AuditLog.setAuditKeys()` unter `auditPrivateKey`/`auditPublicKey` speichert → `signData` warf **immer** „Identity keys not available", d. h. der ganze Erasure-/Report-Pfad war faktisch tot. Korrigiert. Neue Coverage: 5 Tests in `WalletService.test.ts` (2xx→SENT+proof_token, HTTP-Fehler→fail-closed, Netzwerk-Fehler→fail-closed, für Erasure + Report). **UI-Anbindung erledigt (2026-07-13):** die pro-Transaktion-Controls im `DataFlowPanel` („🗑️ Löschung anfordern" / „🚩 Melden") existierten bereits, aber `App.tsx` übergab **kein** `onAction` → Klick war ein No-op. Jetzt ist `handleDataFlowAction(type, decisionId)` verdrahtet: ruft `requestDataErasure`/`reportRelyingParty` (Report mit `window.prompt`-Grund), spiegelt das fail-closed-Ergebnis via `addLog` (Erfolg/Fehler) und lässt das Panel über den Audit-Refresh die neue `ERASURE_REQUESTED`/`REPORT_SENT`-Transaktion zeigen. Der Erasure-Button bleibt disabled, wenn die Transaktion keinen `erasure_endpoint` hat. Coverage: 2 `DataFlowPanel`-Wiring-Tests (Buttons → `onAction` mit korrekter `decision_id`; disabled ohne Endpoint).

**Leitsatz:** *"Alle sind AskMI."*

---

## Legende
- 🔴 P0 — Blocker / Must-Have für nächsten Meilenstein
- 🟡 P1 — Wichtig, sollte bald passieren
- 🟢 P2 — Nice-to-have / Langfristig
- ✅ — Erledigt

---

## Sprint 02 — Big Audit Follow-Ups (2026-06-04)

Quelle: `docs/tasks/SPRINT_02_BIG_AUDIT.md` und
`docs/qa/BIG_AUDIT_CONSTANTS_CONTRACTS_2026-06-04.md`.

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| S2-01 | ✅ | ✅ | Gemeinsame AskMI Runtime-/Demo-Konstanten für Identifier, Env-Namen, Storage-Keys und Scenario-VCTs | `@askmi/shared-types` exportiert die Contracts; aktive Pilot-Flows nutzen sie |
| S2-02 | ✅ | ✅ | Wallet Policy Manifest nicht mehr im Klartext-`localStorage` speichern | Aktive Policy liegt in `SecureStorage`; Legacy-Key wird einmalig migriert und entfernt; Systemdokument erscheint nicht in `getCredentials()` |
| S2-03 | ✅ | ✅ | Active-code Rebrand Guard in CI | `src`, `.github`, Root Configs brechen bei `@mitch/*`, `did:mitch`, `mitch.demo`, `MitchPolicyEvaluator` |
| S2-04 | ✅ | ✅ | Demo-Scenario-Fixtures prüfen/extrahieren | Canonical `ASKMI_SCENARIO_CLAIMS` in `@askmi/shared-types`; Wallet- und Verifier-Backend-Fixtures leiten daraus ab (Backend aliast `birthDate`→`dateOfBirth` an der Protokollgrenze); Frontend-Anzeige-Copy bleibt lokal; `doctor-login` age-Drift (24/35) auf 35 vereinheitlicht |
| S2-05 | ✅ | ✅ | Trust-/StatusList-Test-Fixtures als Testhelper | `@askmi/revocation-statuslist/test-helpers` exportiert `makeStatusListEntry`/`makeStatusListCredential`; `revocation-statuslist`-Tests und `@askmi/integration-tests` nutzen sie ohne Copy/Paste; Bitstring-Encoding bleibt pro Aufrufer lokal (kein geändertes Revocation-Verhalten) |

---

## Legacy-Audit: Unlinkability-Gruppe U-01–U-23 (Traceability)

Die ursprüngliche „Phase 1 — Unlinkability"-Gruppe (`U-01`–`U-23`) stammt aus dem ersten
Master-Backlog (`656a07b`) und wurde beim v1.0-RC-Restructure (`4a19176`) aus der
Tabellenstruktur entfernt (ersetzt durch E-/G-/R-Epics). **Die IDs wurden nicht migriert,
die Arbeit aber überwiegend geliefert.** Vollständiges Audit (2026-06-08, `4a19176` hat nur
README/STATE/BACKLOG editiert, keine Datei gelöscht):

| Legacy-Block | IDs | Status | Wo auf `master` |
|---|---|---|---|
| 1.1 Pairwise-Ephemeral DIDs | U-01–U-03 | ✅ | Spec 111, `shared-crypto/src/pairwise-did.ts` |
| 1.2 Randomisierte Proofs | U-10–U-13 | ⬜ **offen** | [`tasks/SPRINT_PROOF_RANDOMIZATION.md`](tasks/SPRINT_PROOF_RANDOMIZATION.md) (Review 1: B+C, BBS+ deferred) |
| 1.3a Identity Firewall | U-20, U-21 | ✅ | `IDENTITY_ACCESS_DETECTED`, `data-flow` Kategorie `identity` — [`tasks/SPRINT_01_IDENTITY_FIREWALL.md`](tasks/SPRINT_01_IDENTITY_FIREWALL.md) |
| 1.3b Anti-Fingerprinting | U-22, U-23 | ✅ | `wallet-pwa/src/utils/anti-fingerprinting.ts` (Padding + „U-23: Network Timing Jitter") |

**Ergebnis:** Nichts wurde fälschlich gelöscht. Einziges offenes Cluster: U-10–U-13
(= Sprint Proof-Randomization). Enforcement/Blocking von Trackern war bewusst nicht Teil
von 1.3 (nur Sichtbarmachung + Anti-Korrelation).

---

## Video Gap Analysis → Delivery Backlog (2026-05-31)

Quelle für diese Sektion: Analyse der drei Referenz-Demos (Web Wallet, Unified Identity, MCP Agent Identity).
Ziel: miTch auf **produktreife, wiederverwendbare Identity-Flows** heben (nicht nur Tech-Demo).

**Sprint-0-Hinweis (2026-06-04):** Diese Sektion ist der ursprüngliche
Delivery-Backlog aus der Video-Gap-Analyse. Einige Epics wurden danach in den
Phasen 1-4 geschlossen und sind weiter unten als erledigt markiert. Die Zeilen
unten bleiben als Herkunft/Nachverfolgung sichtbar, sind aber nicht automatisch
aktuelle P0-Blocker. Aktuelle operative Evidence liegt in `STATE.md` und
`docs/qa/`; neue Arbeit sollte als frische Sprint-Datei unter `docs/tasks/`
geplant werden.

### EPIC G-100 — E2E Reliability & Predicate Contract Hardening

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-100.1 | 🔴 P0 | ✅ | Determinismus-Root-Cause behoben: clock-abhängige Altersberechnung (`new Date()`) → injizierbares `asOf` durch `evaluatePredicates`, Alters-Mathematik auf kanonische `computeAgeOnDate` (UTC) zentralisiert. **PR #99** (`c069e96`). Vokabular-Drift (a) ist latent (Wallet+Verifier nutzen dieselbe `ageAtLeast`, Hashes matchen) → als separates Konsistenz-Item nach G-100.5/Contract-Adoption verschoben, kein Determinismus-Blocker. | Liquor-Szenario deterministisch grün ✅ (asOf-Tests inkl. 10×-Reproduzierbarkeit; predicates 78/78, policy-engine 319/319 lokal) |
| G-100.2 | 🔴 P0 | ✅ | Versionierter, **EUDI-geformter** Claim/Predicate-Contract: kanonischer `age_over_18` + Format-Binding-Schicht (SD-JWT-VC `age_equal_or_over` unter `urn:eudi:pid:1`; mdoc-PID + AV `eu.europa.ec.av.1` reserviert), Alias-Layer (fail-closed `UnknownClaimError`), `asOf`-Determinismus, ajv-`validateClaimRequest`. Schema in `shared-types` (Zero-Dep-Leaf), ajv in `verifier-sdk`. **PR #98** (`595272f`). Design: [`superpowers/specs/2026-06-10-eudi-claim-contract-design.md`](superpowers/specs/2026-06-10-eudi-claim-contract-design.md). | Versioniertes JSON-Schema + Contract-Tests ✅; SD-JWT-`age_equal_or_over` korrekt; fail-closed ✅ |
| G-100.3 | 🔴 P0 | ✅ | 5-Szenarien E2E-Matrix in CI (Liquor, Doctor, EHDS, Pharmacy, Revoked) | CI bricht bei 1 Szenario-Regression — erledigt via PR #69 (`test(verifier): automate pilot five-scenario smoke matrix`) |
| G-100.4 | 🟡 P1 | ✅ | Correlation IDs über Wallet/Verifier/Issuer: `txn_*` Resolver in `shared-types`; Verifier/OID4VP mintet; Wallet/Policy/Audit/Issuer erhalten und spiegeln die ID. Branch `feat/g100.4-correlation-ids`, lokale Validierung 2026-07-04 grün. | Jede Demo-Transaktion end-to-end tracebar |
| G-100.5 | 🟡 P1 | ⏳ | **EUDI-Interop-Gap (ehrliches Tracking, [#97](https://github.com/Late-bloomer420/miTch/issues/97))**: voller mdoc-`eu.europa.ec.av.1`-Pfad + ECDSA-ZKP (AV-Profil ist mdoc-only, ZKP recommended). Bewusst deferred — Pilot läuft auf SD-JWT-Pfad. | Issue #97 bleibt offen bis mdoc-AV-Pfad + ZKP geliefert oder bewusst verworfen |
| G-100.6 | 🟡 P1 | ✅ | `verifier-browser` (PoC-Stub `mockResponse: success:true`, Signaturprüfung übersprungen) → `archive/prototypes/` (git mv, History erhalten) + CI-Guard `guard:archived-imports`. **PR #100** (`efc6950`). | Paket in `archive/` ✅; CI bricht bei Re-Import aus aktivem Tree ✅ (negativ-getestet) |
| G-100.7 | 🟢 P2 | ✅ | **Flaky Timing-Test** behoben: `anti-oracle.test.ts` misst jetzt den **Pro-Aufruf-Durchschnitt** über 2000 Iterationen (`< 0.1ms`) statt einer Einzelmessung `< 1ms` — Jitter wird amortisiert. 3× lokal stabil 14/14. | Kein last-abhängiger CI-Flake mehr aus anti-oracle ✅ |

### EPIC G-110 — QR + Deep-Link Handoff

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-110.1 | 🔴 P0 | ✅ | Verifier zeigt immer QR + „Open in Wallet“ Link. Bereits in `VerifierPanel` vorhanden; am 2026-07-04 mit `VerifierPanel.test.tsx` für alle 5 Szenarien gegen SVG-QR + Wallet-Link-Parameter abgesichert. | Dual Path (Scan/Click) in allen 5 Szenarien |
| G-110.2 | 🟡 P1 | ⏳ | Handoff-State-Machine (created/scanned/opened/completed/expired) | UX zeigt klaren Zustand + Retry |
| G-110.3 | 🟡 P1 | ⏳ | Ablauf-/TTL-Handling für Requests | Abgelaufene Requests werden fail-closed und verständlich kommuniziert |

### EPIC G-120 — Auth Window / Popup Credential Presentation

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-120.1 | 🔴 P0 | ⏳ | Branded Auth-Popup (`window.open`) inkl. Callback/Close | Verifier erhält garantiert Callback oder Timeout |
| G-120.2 | 🟡 P1 | ⏳ | Popup Blocker Fallback (same-tab flow) | Flow funktioniert auch ohne Popup-Rechte |
| G-120.3 | 🟡 P1 | ⏳ | Session-Binding zwischen opener und wallet | Kein Cross-Tab/Cross-Origin Confusion möglich |

### EPIC G-130 — Passkey-first Wallet Unlock

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-130.1 | 🔴 P0 | ✅ | Passkey-Onboarding als erzwungener Default vor Wallet-/Presentation-Nutzung; bei WebAuthn-fähigem Gerät wird ein fehlender Passkey zuerst registriert und danach für den Unlock verlangt. **Gelandet via PR #103 (`ab4d970`, enforce passkey onboarding) + PR #104 (`20478f0`, Get/Refresh credential UI), inkl. Model-A device-bound passkey, durable vault, first-run welcome, expliziter Reset.** | Wallet startet nicht offen; Demo-Flow ist erst nach Passkey-Unlock bedienbar ✅ |
| G-130.2 | 🟡 P1 | ⏳ | Recovery/Fallback UX (device unavailable) | Klarer Fallback ohne Dead-End |

### EPIC G-140 — Consent & Disclosure UX

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-140.1 | 🟡 P1 | ✅ | Layer-2 requested/allowed/withheld sichtbar und proximity mdoc policy-geroutet (#112/#114/#115/#116); Pro-Claim-Sensitivität + dauerhaftes erstklassiges DataFlow-Panel (#119/#120) | Nutzer sieht exakt was verlangt, autorisiert, geteilt oder zurückgehalten wurde, inkl. neutraler Sensitivität pro Claim; DENY bleibt sichtbar |
| G-140.2 | 🟡 P1 | ⏳ | Ergebnis-Screen + Return-to-verifier UX | Erfolgs-/Fehler-Rückgabe konsistent |

### EPIC G-150 — “Sign in with AskMI” Integration Kit

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-150.1 | 🟡 P1 | ⏳ | OIDC-style Adapter + Button SDK | Referenzintegration läuft in Demo-App |
| G-150.2 | 🟡 P1 | ⏳ | Server Middleware (Node) für Verifier | Minimal-Setup < 30min dokumentiert |

### EPIC G-160 — Partner Reuse & Trust Onboarding

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-160.1 | 🟡 P1 | ⏳ | Partner-/Verifier-Registry + trust onboarding | Neuer Partner kann ohne Code-Änderung onboardet werden |
| G-160.2 | 🟢 P2 | ⏳ | Reusable policy packs (internal/external partners) | Standard-Packs versioniert verfügbar |

### EPIC G-170 — MCP / Agent Identity Surface

| ID | Prio | Status | Beschreibung | Akzeptanzkriterium |
|---|---|---|---|---|
| G-170.1 | 🟢 P2 | ⏳ | MCP tools: issue / request-proof / verify / did ops | Agent-Flow funktioniert mit Audit-Trail |
| G-170.2 | 🟢 P2 | ⏳ | Delegated-authority guardrails | Agent darf nur policy-konforme Aktionen |

---

---

## Phase 0 — Foundation (DONE ✅)

Alle P0 + P1 Gaps geschlossen. 34/34 Turbo Tasks, 155+ Tests, 0 Audit Vulns.

| ID | Status | Beschreibung |
|---|---|---|
| G-01 | ✅ | DID Resolution + Signaturverifikation |
| G-02 | ✅ | StatusList2021 Revocation Runtime (Fail-Closed Bug gefixt) |
| G-03 | ✅ | Policy Determinism + 31 Deny Reason Codes + Anti-Oracle |
| G-04 | ✅ | Anti-Replay Binding (Canonicalization, Nonce Store, TTL) |
| G-05 | ✅ | eID Issuer Simulator (SD-JWT VC, ES256, DID Document) |
| G-06 | ✅ | Credential Persistence (AES-256-GCM + IndexedDB) |
| G-07 | ✅ | Key Separation (ECDH-P256 enc vs ECDSA signing) |
| G-08 | ✅ | JWE Encrypted Credentials at Rest |
| G-09 | ✅ | L2/Blockchain Anchoring Stubs |
| G-10 | ✅ | WebAuthn Step-Up + Challenge Expiry |
| AI-01–06 | ✅ | Alle Audit Issues geschlossen |
| EHDS T-A1–D1 | ✅ | 12 EHDS Tasks komplett |

---

## Phase 1 — Unlinkability ("Alle sind AskMI") ✅

### 1.1 Pairwise-Ephemeral DIDs (Spec 111)
| ID | Status | Beschreibung | Spec |
|---|---|---|---|
| U-01 | ✅ | `pairwise-did.ts` — did:peer Generation + HKDF Derivation | Spec 111 |
| U-02 | ✅ | did:peer Resolution in `did.ts` (inline, kein Netzwerk) | Spec 111 |
| U-03 | ✅ | Unlinkability Tests (Cross-Verifier, Cross-Session, Anti-Korrelation) | Spec 111 |
| U-04 | ✅ | Key Shredding nach Interaktion (EphemeralKey Integration) | Spec 111 |
| U-05 | ✅ | Policy Engine: Pairwise DID in Proof-Generierung einbinden | Spec 111 |

### 1.2 Demo Reliability & Handoff (Phase 1.3 Stabilisierung) ✅
| ID | Status | Beschreibung |
|---|---|---|
| G-100 | ⚠️ teilweise | Erster `AGE_NOT_VERIFIED`-Fix (Claim-Normalisierung `dateOfBirth`) — **hielt nicht deterministisch**. Vollständige Behebung jetzt via EPIC G-100 oben (G-100.1/.2, versionierter EUDI-Contract + `asOf`). Diese Zeile bleibt nur als History. |
| G-110 | ✅ | Robuster QR/Deep-Link Handoff (`SCANNED`, `EXPIRED` Zustände + `/notify-scan`) |

---

## Phase 2 — Architecture & Modularity ✅

### 2.1 Decoupling (Refactoring Phase 6)
| ID | Status | Beschreibung |
|---|---|---|
| R-01 | ✅ | `IStorageAdapter` — Entkopplung von SecureStorage und IndexedDB |
| R-02 | ✅ | `WalletService` Decomposition — Zerlegung in Repositories (Credential, Policy, Presentation) |

---

## Phase 3 — Identity Ecosystem & UX ✅

### 3.1 Integrations
| ID | Status | Beschreibung |
|---|---|---|
| G-130 | ✅ | Passkey-First Unlock (Windows Hello / FaceID / TouchID) |
| G-120 | ✅ | Secure Auth Popups (`window.opener` bridge) |
| G-150 | ✅ | OIDC-style "Sign in with AskMI" Ready |

---

## Phase 4 — Final Compliance & TSL ✅

| ID | Status | Beschreibung |
|---|---|---|
| E-40 | ✅ | Live EUDI Trust List (TSL) Integration |
| E-41 | ✅ | TSL Signature Verification (eIDAS 2.0 Compliance) |
| E-42 | ✅ | Functional Coverage 100% (Technical) |

---

## Phase 2 — EUDI / eIDAS 2.0 Kompatibilität 🟡

### 2.1 OpenID-Protokolle
| ID | Prio | Beschreibung | Standard |
|---|---|---|---|
| E-01 | ✅ | OID4VP (OpenID for Verifiable Presentations) — E-01a–E-01d complete | OIDF.OID4VP |
| E-02 | ✅ | OID4VCI (OpenID for Verifiable Credential Issuance) — 32 tests | OIDF.OID4VCI |
| E-03 | ✅ | SIOPv2 (Self-Issued OpenID Provider v2) — 15 tests | OIDF.SIOPv2 |
| E-04 | ✅ | OAuth 2.0 Attestation-Based Client Auth — attestation+pop chain | RFC6749 ext |
| E-05 | ✅ | DPoP (Demonstrating Proof-of-Possession) — 13 tests | RFC 9449 |

### 2.2 Credential-Formate
| ID | Prio | Beschreibung | Standard |
|---|---|---|---|
| E-10 | ✅ | SD-JWT VC Compliance (draft 11) — 17 tests, vct/cnf/kb-jwt | I-D.ietf-oauth-sd-jwt-vc |
| E-11 | ✅/🟡 | ISO/IEC 18013-5 (mdoc) Support — mobiler Führerschein — `@askmi/mdoc`: CBOR Codec, COSE Sign1, **COSE_Mac0** (HMAC-SHA-256, ECDH+HKDF Key Derivation), Offline-Verifikation (5-Step), x5chain, DeviceResponse Parser, **mdoc-builder** (`buildMdocDocument()` Issuance-Pipeline) — 169 tests; **Wallet** (73/73): `addMdocCredential()`, Presentation-Path, Demo-Seed; **Verifier** (52/52): `verifyMdocPresentation()`, `mso_mdoc` OID4VP-Typen; **Hybrid Issuance**: `mso_mdoc` in OID4VCI, issuer-mock `POST /credential/mdoc` (mDL, 7 Elements). **Ehrliche Grenze:** EU-AV-Profil `eu.europa.ec.av.1` + ECDSA-ZKP ist nicht vollständig wired und wird in G-100.5 / Issue [#97](https://github.com/Late-bloomer420/miTch/issues/97) offen gehalten. | ISO.18013-5 |
| E-12 | 🟢 | Designated Verifier Signatures (JOSE draft 1) | DVS-JOSE |
| E-13 | ✅ | High Assurance Interoperability Profile — direct_post.jwt, verifier attestation | OpenID4VC HAIP |

### 2.3 Kryptographie (BSI/SOG-IS Konformität)
| ID | Prio | Beschreibung |
|---|---|---|
| E-20 | ✅ | brainpoolP256r1 Support (noble-curves, RFC 5639 §3.4) — 7 tests |
| E-21 | ✅ | brainpoolP384r1 Support (RFC 5639 §3.6, SHA-384) — keygen, sign, verify, ECDH, key export, 7 tests + 2 cross-curve isolation |
| E-22 | 🟢 | brainpoolP512r1 Support (optional, höchste Sicherheit) |
| E-23 | ✅ | ECDH secp256r1 + HMAC-SHA2 MAC Verification — 10 tests |

### 2.4 Regulatory Compliance
| ID | Prio | Beschreibung | Referenz |
|---|---|---|---|
| E-30 | ✅ | CIR 2024/2977 Compliance (PID + EAA Anforderungen) — 100% (Batch Issuance complete) | EU Implementing Reg |
| E-31 | ✅ | CIR 2024/2979 Compliance (Integrität + Brainpool + Hardware Binding) | EU Implementing Reg |
| E-32 | ✅ | CIR 2024/2982 Compliance (Protokolle + mdoc Proximity + GDPR Rights) | EU Implementing Reg |
| E-33 | ✅ | CIR 2024/2981 — Zertifizierungsanforderungen verstehen + LoA High Readiness | EU Implementing Reg |

| E-34 | 🟢 | CIR 2025/846 Cross-Border Identity Matching | EU Implementing Reg |
| E-35 | 🟢 | CIR 2025/848 Relying Party Registration | EU Implementing Reg |
| E-36 | 🟢 | DSGVO Verarbeitungsverzeichnis (Art. 30) | DSGVO |
| E-37 | 🟢 | Betroffenenrechte-Implementierung (Auskunft, Löschung, Berichtigung) | DSGVO |
| E-38 | ✅ | EHDS Compliance (T-C2, T-C3) — Secondary Use Opt-Out + Localized Terms | EHDS |

### 2.5 Pilot & Production Readiness (New Gaps)
| ID | Prio | Beschreibung | Referenz |
|---|---|---|---|
| E-40 | ✅ | EUDI Trust List Integration (TSL) — eIDAS Node Connector | Pilot Blocker |
| E-41 | ✅ | OID4VCI Batch Issuance Support (§7) | CIR 2024/2977 |
| E-42 | ✅ | Formal Certification Process (Common Criteria Evaluation) — Security Target (ST) documented | CIR 2024/2981 |
| E-45 | 🟡 | Visual Credential Rendering (W3C Spec) — Sandboxed SVG/Mustache & HTML Branding | W3C VC-Render |

---

## Phase 5 — Visual & Branding (UX Layer) 🟡

Basierend auf: `W3C Verifiable Credential Rendering Methods v1.0`

> **Hinweis (2026-07-13):** Eine **nicht verdrahtete** Referenz-Implementierung dieser Zeilen existiert bereits im Code (parked, TODO-Marker): `wallet-pwa/src/components/CredentialRenderer.tsx` (V-01 `renderMethod`, V-03 svg-mustache, V-04 `verifyDigestMultibase`), `wallet-pwa/src/components/SecureIframeRenderer.tsx` (V-02 sandboxed CSP-iframe), `wallet-pwa/src/components/CredentialCard.tsx` (Branded Card). Offen = Einbindung in die Wallet-UI, nicht Neubau.

| ID | Prio | Beschreibung | Standard |
|---|---|---|---|
| V-01 | 🟡 | `renderMethod` Property Support in SD-JWT VC Parser — Impl. parked in `CredentialRenderer.tsx` (unwired) | W3C VC-Render |
| V-02 | 🟡 | Sandboxed Iframe Renderer mit strikter CSP (No-Tracking Enforcement) — Impl. parked in `SecureIframeRenderer.tsx` (unwired) | W3C §4.2 |
| V-03 | 🟢 | `svg-mustache` Template-Engine Integration für Branded Cards — Impl. parked in `CredentialRenderer.tsx` (unwired) | W3C §3.1.1 |
| V-04 | 🟢 | Cryptographic Digest Verification (`digestMultibase`) für Templates — Impl. parked in `CredentialRenderer.tsx` (unwired) | W3C §3.1.3 |

---

## 5. Compliance Status (CIR 2024/2981 & 2982)
- **Total requirements:** 53
- **Implemented:** 52 ✅
- **Partial:** 1 🟡 — formal Common Criteria certification (CC conformance, E-42; external evaluation pending)
- **Compliance Score:** 98% (52/53) — consistent with [`../STATE.md`](../STATE.md) and [`compliance/EUDI_CIR_MATRIX.md`](compliance/EUDI_CIR_MATRIX.md)

---

## Phase 3 — Security Hardening (Salt Typhoon Patterns) 🟡

Basierend auf: `memory/miTch_security_patterns_memory.md` — *lokale OpenClaw-Workspace-Notiz, nicht im Repo und nicht portabel (siehe `DOCS_CANON.md` → „Agent and Memory Surfaces").*

| ID | Prio | Beschreibung | Angriffsmuster |
|---|---|---|---|
| S-01 | ✅ | `verifier_fingerprint` in Policy Manifest Spec | Fake Verifier Spoofing |
| S-02 | ✅ | `manifest_version` Monotonic Counter + `manifest_hash` | Manifest Rollback |
| S-03 | ✅ | Input Validation Schema (Whitelist-basiert) für Policy Parser | Claim-Name Injection |
| S-04 | ✅ | Komponenten-Isolations-Modell (Engine/Consent/Audit) | Internal Privilege Escalation |
| S-05 | ✅ | Zero Trust intern dokumentieren + implementieren | Chained Attacks |
| S-10 | 🟡 | Formales Threat Model (STRIDE) — ADR-009: STRIDE-Tabelle vollständig (22 Einträge, alle belegt), 3 Szenarien, 4 Gaps dokumentiert. Status PROPOSED — externer Security Review offen (menschliche Vorbedingung) | BSI TR-02102 + EUDI-CIR Risiko-Assessment |
| S-11 | ✅ | **Enforcement-Layer schuetzt Health/Professional-Vokabular** ([Issue #122](https://github.com/Late-bloomer420/miTch/issues/122)) — geschlossen/validiert 2026-07-01: `bloodGroup`/`allergies`/`activeProblems`/`emergencyContacts`/`medication`/`dosageInstruction`/`refillsRemaining`/`role`/`licenseId` sind Enforcement-seitig `VULNERABLE`; legitime Doctor/EHDS/Research/Pharmacy-Regeln optieren explizit mit `minimumLayer: VULNERABLE` ein. Regressionen sichern, dass WELT/default-Verifier `bloodGroup` und Layer-1-Verifier `licenseId` mit `LAYER_VIOLATION` verlieren, waehrend autorisierte Layer-2 Demo-Flows weiter gruen bleiben. | Low-Layer-Verifier erhalten keine Layer-2-Gesundheits-/Professional-Claims mehr; 46/46 Turbo-Tasks + rebrand guard gruen |

---

## Phase 4 — Controlled Insight (Konzept) 🟢

Basierend auf: `docs/00-welt/concept_controlled_insight.md`

| ID | Prio | Beschreibung |
|---|---|---|
| CI-01 | 🟢 | Stufe 0 (Opaque) — Default, bereits implementiert durch Unlinkability |
| CI-02 | 🟢 | Stufe 1 (Mirror) — Lokale Analyse auf Device, Muster-Visualisierung |
| CI-03 | 🟢 | Stufe 2 (Delegate) — Zeitlich begrenzte, granulare Freigabe an Dienste |
| CI-04 | 🟢 | Datenwert-Dashboard (Visualisierung) |
| CI-05 | 🟢 | Delegations-Management UI mit Crypto-Shredding bei Widerruf |

---

## Housekeeping 🟢

| ID | Prio | Beschreibung |
|---|---|---|
| H-01 | ✅ | ESLint Sweep: 0 errors, 0 warnings (war 170 warnings + 2 errors) |
| H-02 | 🟢 | `mitch-temp` Repo archivieren |
| H-03 | 🟢 | `AskMI---Policy-Enforcement-Layer` Repo löschen |
| H-04 | ✅ | GitHub `main` Branch löschen (nur `master` behalten) — war bereits gelöscht |
| H-05 | ✅ | `.gitattributes` mit `* text=auto eol=lf` (Line-Ending Fix) |
| H-06 | ✅ | Demo E2E Flow testen (5 Szenarien) — 1812 Tests pass |
| H-07 | ✅ | Uni-Präsentation vorbereiten — OUTLINE.md + ARCHITECTURE.md |
| H-08 | ✅ | Branch/PR-Consolidation (2026-05-27): alle 10 offenen PRs auf `master` aufgelöst, Branch-Sprawl 22→3. Nur net-new value gesalvaged (Trust Kit #35, B2B-Use-Cases + Agent-Skills + ADR-010 #37, MCP-Freeze-Decisions #38, Verifier fail-closed + no-PII-log #34, PII-Substring-Testfix #36, `_tmp_*` gitignore #39); stale-base PRs ohne Wert mit Begründung geschlossen (#14/#16/#17/#18/#24/#26/#27/#30). **Kein Paperclip auf master** (Pflicht erfüllt); Suite 100% grün (44/44 Tasks, 1787 Tests) |
| H-09 | ✅ | npm scope alignment (2026-06-04): drei veröffentlichte Pakete als `@askmi/shared-types`, `@askmi/shared-crypto`, `@askmi/revocation-statuslist`; vollständiger Workspace-Rebrand auf AskMI / `@askmi/*`; PR #66 auf `master` gemerged |
| H-10 | ✅ | Sprint 0 Repo Truth Alignment: `STATE.md`, `docs/BACKLOG.md`, `docs/SESSION_HISTORY.md`, `docs/qa/`, `AGENTS.md`, `CLAUDE.md` und historische Session-Dateien konsolidieren. **2026-06-20 Pass (Branch `docs/h10-truth-alignment`):** master-Pointer #81→#104 korrigiert, G-130.1 ✅, Status-Widerspruch (Phase-3-Rollup vs. Video-Gap-Granular) geklärt, Capsule-Sig-Resolution als QA-Evidenz abgelegt, SESSION_HISTORY Session 18 ergänzt. **2026-06-24 Pass (Branch `docs/g140-surfacing-truth-align`):** master-Pointer auf `e9bec3c`/#120 (G-140 Surfacing #119/#120) aktualisiert; **`AGENTS.md`/`CLAUDE.md` Review erledigt** — Drift korrigiert (Turbo-Task-Zahl 45→46; `layer-resolver`-Beschreibung korrekt: Protection-Layer + Sensitivity-View). **2026-06-24 Abschluss:** `docs/qa/`-Sichtung erledigt — Index [`docs/qa/README.md`](qa/README.md) ergänzt (alle Dateien als datierte Evidenz-Records bestätigt, kein Task-Tracking). **H-10 geschlossen.** |

---

## Architecture Decision Records (ADR-001–012)

Alle ADRs liegen in `docs/03-architecture/mvp/`. Zusätzlich in `docs/compliance/ADR/`: `ADR-009.md` (WebAuthn Native Verifier — anderes Thema als ADR-009 Threat Model) und `ADR-010.md` (Regulatory-Positioning Boundary for Age Verification — gesalvaged via #37, renumbered von 013).

| ADR | Titel | Status | Bezug |
|-----|-------|--------|-------|
| ADR-001 | Credential Stack (SD-JWT VC) | ACCEPTED | im Repo umgesetzt |
| ADR-002 | WebAuthn Native Strategy | ACCEPTED | im Repo umgesetzt |
| ADR-003 | Revocation Strategy (StatusList2021) | ACCEPTED | im Repo umgesetzt |
| ADR-004 | Consent UX Strategy (Human-in-the-Loop First) | PROPOSED | dokumentiert |
| ADR-005 | Metadata Minimization Strategy (Unlinkability First) | PROPOSED | dokumentiert |
| ADR-006 | Recovery Strategy (Device Loss) | PROPOSED | dokumentiert; REFACTORING_ROADMAP |
| ADR-007 | AI Orchestrator Integration (Scoped Delegation) | PROPOSED | dokumentiert |
| ADR-008 | Batch Credentials Strategy (Unlinkable Multi-Credential) | PROPOSED | dokumentiert |
| ADR-009 | Threat Model (STRIDE) | PROPOSED | STRIDE-Tabelle + Szenarien + Gaps vollständig; externer Review offen |
| ADR-010 | TEE Integration Strategy | PROPOSED | dokumentiert; deferred T-31 |
| ADR-011 | Claim-Level Encryption (Per-Claim SD-JWT) | PROPOSED | dokumentiert; deferred F-07 |
| ADR-012 | ISO 18013-5 mdoc & Offline Verification | PROPOSED | dokumentiert; E-11 komplett: Offline-Verifikation + COSE_Mac0 (169 tests) + Wallet (73/73) + Verifier (52/52) + Hybrid Issuance (builder + issuer-mock) |

---

## Referenzen

### EU/eIDAS
- ARF: https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- EUDI Wallet Repos: https://github.com/eu-digital-identity-wallet
- STS Roadmap: https://github.com/orgs/eu-digital-identity-wallet/projects/29/views/2
- Deutsche Architektur: https://gitlab.opencode.de/bmi/eudi-wallet/eidas-2.0-architekturkonzept
- EHDS: https://health.ec.europa.eu/ehealth-digital-health-and-care/european-health-data-space-regulation-ehds_en

### Implementing Regulations (2024-2025)
- CIR 2024/2977 (PID + EAA): https://data.europa.eu/eli/reg_impl/2024/2977/oj
- CIR 2024/2979 (Integrity): https://data.europa.eu/eli/reg_impl/2024/2979/oj
- CIR 2024/2980 (Notifications): https://data.europa.eu/eli/reg_impl/2024/2980/oj
- CIR 2024/2981 (Certification): https://data.europa.eu/eli/reg_impl/2024/2981/oj
- CIR 2024/2982 (Protocols): https://data.europa.eu/eli/reg_impl/2024/2982/oj
- CIR 2025/846 (Cross-Border): https://data.europa.eu/eli/reg_impl/2025/846/oj
- CIR 2025/848 (RP Registration): https://data.europa.eu/eli/reg_impl/2025/848/oj

### Standards
- SD-JWT: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
- OID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OID4VCI: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- SIOPv2: https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
- ISO 18013-5: https://www.iso.org/standard/69084.html
- BBS+ Signatures: https://www.w3.org/TR/vc-di-bbs/
- did:peer: https://identity.foundation/peer-did-method-spec/

### Intern
- Policy Manifest v2.0: `docs/00-welt/mitch_policy_manifest.md`
- Controlled Insight: `docs/00-welt/concept_controlled_insight.md`
- Spec 111: `docs/specs/111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md`

#### Lokale Workspace-Notizen (nicht im Repo, nicht portabel)
> Diese Dateien liegen ausschließlich in der lokalen OpenClaw-Workspace-Memory, nicht im Repo-Commit. Beim Klonen ohne den Workspace sind die Pfade tote Verweise. Siehe `DOCS_CANON.md` → „Agent and Memory Surfaces".
- Unlinkability Vision: `memory/unlinkability-vision.md`
- Security Patterns: `memory/miTch_security_patterns_memory.md`
- EHDS Research: `memory/eudi-compliance-research.md`
