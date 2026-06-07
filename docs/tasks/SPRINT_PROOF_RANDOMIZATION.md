# Sprint: Proof Randomization (Unlinkability Phase 2)

Stand: 2026-06-08
Backlog-Bezug (Legacy): U-10, U-11, U-12, U-13 (original "Phase 1 — Unlinkability / 1.2 Randomisierte Proofs")
Status: Review 1 entschieden; Implementierung increment-weise

## Herkunft / Audit-Lineage

Diese Items stammen aus dem ersten Master-Backlog (`656a07b`, Sektion
"Phase 1 — Unlinkability → 1.2 Randomisierte Proofs"). Beim v1.0-RC-Restructure
(`4a19176`) wurde die `U-`-Taxonomie aus `BACKLOG.md` entfernt und durch das
E-/G-/R-Epic-Schema ersetzt. Vollständiges Audit (2026-06-08):

| Legacy-Block | IDs | Status |
|---|---|---|
| 1.1 Pairwise-Ephemeral DIDs | U-01–U-03 | ✅ geliefert (Spec 111, `pairwise-did.ts`) |
| **1.2 Randomisierte Proofs** | **U-10–U-13** | ⬜ dieser Sprint |
| 1.3 Transparency Layer | U-20–U-23 | ✅ geliefert (Sprint 1 + anti-fingerprinting) |

`4a19176` editierte nur README/STATE/BACKLOG (keine Datei gelöscht). Kein anderer
Commit hat Backlog-IDs gedroppt. Nichts ging verloren — U-10–U-13 sind das einzige
offene Cluster.

## Sprint-Ziel

Verhindern, dass derselbe Credential bei wiederholter Präsentation einen linkbaren
Proof-Output erzeugt. Selbst bei pairwise DIDs ist heute der **Holder-Binding-Key
(`cnf`) + die Issuer-Signatur** ein stabiler Cross-Verifier-Korrelator.

## Scout-Befund (2026-06-08, master)

Vorhanden:
- `pairwise-did.ts`, `ephemeral-key.ts`/`ephemeral.ts` (Letztere sind **Crypto-Shredding**,
  nicht Holder-Binding).
- `sd-jwt-vc.ts`: `cnf`-Claim, `createKbJwt(payload, holderPrivateKey)`,
  `validateKbJwt(kbJwt, holderPublicKey)`.
- OID4VCI Batch Issuance (E-41) — mehrere Credentials pro Session ausstellbar.
- `WalletService.addCredential(...)`.

Lücke: kein BBS+ (0 Dateien), kein Single-Use-/Pool-Management, Holder-Key wird
über Präsentationen wiederverwendet.

## Review 1 — Krypto-Ansatz (Entscheidung 2026-06-08)

Bewertete Optionen:

| Option | Bewertung |
|---|---|
| A — BBS+ Multi-Show ZKP | Stärkste Unlinkability, aber nicht im Code, WASM-Perf/Browser-Risiko, kein EUDI-Pflichtprofil. **Future-Option, dokumentiert.** |
| B — SD-JWT Ephemeral Holder Binding | Pro Credential ein eigener Holder-Key statt eines stabilen. Baut auf `sd-jwt-vc.ts`. |
| C — Single-Use-Credentials (Batch) | Frisches Credential je Präsentation aus Batch-Pool; unlinkbar durch Nicht-Wiederverwendung. Nutzt E-41. |

**Entscheidung: B + C als Übergangslösung (EUDI-konform), A (BBS+) als dokumentierte
Future-Phase, U-13 (Blinded Issuance) als Phase 2.**

Begründung: B+C nutzt vorhandene, standardkonforme Bausteine (SD-JWT + Batch-Issuance),
liefert echte Anti-Linkability ohne BBS+-Risiko und ohne Protokollbruch. Reines
Re-Binding eines bestehenden `cnf` würde die Issuer-Signatur brechen — deshalb muss
der unterschiedliche Holder-Key **bei Issuance pro Batch-Member** entstehen (B), und
die Wallet wählt pro Präsentation einen ungenutzten Member (C).

### Akzeptanzkriterien (Review 1)

- Zwei Präsentationen "desselben" logischen Credentials zeigen unterschiedliche
  `cnf`-Holder-Keys und unterschiedliche Issuer-Signaturen.
- Keine Wiederverwendung eines Single-Use-Members ohne explizite Pool-Erschöpfungs-Logik.
- Bestehende Single-Credential-Flows bleiben kompatibel (kein Zwang zu Batch).
- Keine falsche Behauptung kryptografischer Multi-Show-Unlinkability (das wäre BBS+).

## Review 2 — Bauplan (increment-weise)

### Increment 1 — Single-Use Credential Pool (Wallet, additiv, kein Protokollbruch)

- `shared-types`: `CredentialPoolMember`, `CredentialPoolState`, Pool-Policy
  (`single_use` | `reuse`).
- Wallet-Util `credential-pool.ts`: aus einer Gruppe batch-ausgestellter Members
  einen **ungenutzten** wählen, als genutzt markieren, Erschöpfung melden
  (fail-closed: keine stille Wiederverwendung).
- TDD: Auswahl rotiert, markiert genutzt, meldet Erschöpfung, Single-Credential-Fallback.

### Increment 2 — Ephemeral Holder Binding bei Batch-Issuance

- Issuer-Mock/OID4VCI: pro Batch-Member eigener Holder-Keypair → unterschiedlicher
  `cnf`. Wallet speichert privaten Holder-Key je Member.
- Präsentation nutzt den Member-spezifischen Holder-Key für `createKbJwt`.
- TDD: Roundtrip build→present→verify pro Member grün; zwei Member ⇒ verschiedene `cnf`.

### Increment 3 — DataFlow-Transparenz (ehrliche Aussage)

- Anzeige "Einmal-Credential verwendet (nicht wiederverwendbar)" statt Multi-Show-Claim.
- Kein Risk-Score; faktische Aussage.

### Nicht im Sprint

- BBS+ (A) — eigener Future-Sprint.
- U-13 Blinded Issuance (Issuer-Verifier Collusion Resistance) — Phase 2.
- Echte kryptografische Multi-Show-Unlinkability eines einzelnen Credentials.

## Merge-blockierende Tests pro Increment

Siehe je Increment oben; zusätzlich: bestehende `shared-crypto`, `oid4vp`,
`wallet-pwa` Suiten bleiben grün.
