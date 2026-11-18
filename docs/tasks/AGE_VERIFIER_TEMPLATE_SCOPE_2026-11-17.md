# Schlanke Altersprüfungs-Vorlage — Scope, Befundlage, nächster Schritt (2026-11-17)

**Status:** Entscheidungsvorlage (Planung). Kein Implementierungs-, Sicherheits- oder Interop-Nachweis.
**Quellstand:** `master` @ `58d0af9`; offene PR-Branches wie unten genannt, statisch gelesen am 2026-11-17.
**Nicht ausgeführt:** keine Tests, kein Build, keine Wallet. Alle Aussagen unten sind Quelltext-Lektüre
mit Datei-/Zeilenangabe, sofern nicht als PR-Angabe gekennzeichnet.
**Nicht verfügbar:** Entire Brain/Trails (`entire` nicht installiert). Fallback gemäß
`.entire/agent-guide.md`: direkte Quellinspektion, PR-Texte, Issues #97/#264, `docs/qa/`.

Dieses Dokument ersetzt weder #97, #170–#173 noch die Audit-Befunde `API-01`..`API-07`
([qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md](../qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md)).
Es ordnet sie für **ein** Ziel.

---

## 1. Ziel in einem Satz

> Ein Dienstleister stellt eine Altersanfrage. Eine kompatible Wallet präsentiert einen passenden
> Nachweis. Der Verifier prüft ihn und gibt der Anwendung ein begrenztes Ergebnis zurück.

**Nicht Teil der Vorlage:** eigene Wallet, Gesundheitsfälle, Sync, PQC, Anchoring, MCP-Server,
Policy-Engine auf Wallet-Seite. Diese Teile werden nicht gelöscht, aber sie sind **keine
Voraussetzung** und keine Abnahmebedingung.

## 2. Was der aktive Pfad heute tatsächlich tut (Fakten, statisch)

Aktiver Pfad: `verifier-demo/backend` `POST /oid4vp-present`
(`src/apps/verifier-demo/backend/src/app.ts:487-593`).

| Schritt | Ort | Befund |
|---|---|---|
| Session/One-shot | `app.ts:503-508` | Synchrone Reservierung; jeder Versuch terminal. In-Memory, ein Prozess (dokumentiert in [qa/ACTIVE_AGE_PROFILE_2026-10-25.md](../qa/ACTIVE_AGE_PROFILE_2026-10-25.md)). |
| Aussteller-Schlüssel | `app.ts:522-537` | Aus `iss` über `issuerKeyResolver`; vom Wallet gesendeter `issuer_jwk` wird ignoriert. |
| Signatur, Trust, Status, KB-JWT | `oid4vp/src/demo-flow.ts:326-432` via `validateSDJWTPresentation(checkTrust: true, checkRevocation: true)` | KB-JWT mit `aud`, `nonce`, `sd_hash`, 600 s. **Trust-Liste ohne Anker-Schlüssel ungeprüft akzeptiert** (`API-05`, #240). **Status-Liste ohne Signaturprüfung** (`API-05`). |
| Disclosures | Aufruf `demo-flow.ts:423` → `shared-crypto/src/sd-jwt-vc.ts:405-407` | Auf `master` permissiv: `extractDisclosedClaims` überspringt Disclosures mit unbekanntem Digest per `continue` (#264). PR #288 stellt auf strikt um — **und trifft damit genau diesen aktiven Pfad**. |
| Profil/Eligibility | `backend/src/active-profile.ts` | Akzeptiert nur genau einen Claim `age`, **numerisch**, `>= 18`. |
| Antwort an Anwendung | `app.ts:567-574` | `{ eligible: true }`, `disclosedClaims: null`. |

**Konsequenz (Fakt):** Die Anwendung bekommt ein Boolean, **der Verifier bekommt das genaue Alter**.
Damit ist die Frage „Was kommt tatsächlich beim Verifier an?“ beantwortet: das numerische Alter, nicht nur ein Boolean (siehe auch #97, „Current evidence boundary“).

## 3. Befunde aus den letzten PRs, bezogen auf die Vorlage

| PR | Inhalt (laut PR-Text) | Relevanz für die Vorlage | Einordnung |
|---|---|---|---|
| #288 | Strikter Disclosure-Parser am OID4VP-Präsentationspfad (#264) | **Direkt** — aktiver Verifier-Pfad (siehe §2) | Voraussetzung. Merge-Kandidat zuerst. |
| #276 | Trust-Liste fail-closed außer `ASKMI_TRUST_MODE=dev` (#240) | **Direkt** — `checkTrust: true` im aktiven Pfad | Voraussetzung. Offen: JWKS-Auswahl per `kid` (`keys[0]`). Verhaltensbruch braucht Owner-Freigabe (im PR benannt). |
| #287 | Ehrliche Demo-Texte; isolierter Boolean-Test mit vorhandenen Primitiven | Indirekt — zeigt Machbarkeit, **nicht** aktiven Pfad | Erkundung. Kein Profil, kein ZK, keine Unverknüpfbarkeit. |
| #289 | Z3-Modell einer idealisierten One-shot-Session (#197) | Indirekt — Modell, nicht Code | Forschung. Keine Freigabe. |
| #279 | Inventar der Reduced-Assurance-Modi (#242) | Hilfreich als Checkliste für die Vorlage | Doku, nicht ausgeführt. |
| #275 | Strikte `did:web`-Bindung in der Policy-Engine (#238) | Wallet-Seite | Nicht Voraussetzung der Vorlage. |
| #277, #278 | Demo-Wallet-Isolation; Popup-Bridge-Origin (#239) | Eigene Wallet | Nicht Voraussetzung der Vorlage. |
| #280, #281 | Scope-Split der 2026-11-03-Audit-Doku aus #247 | Hygiene | Unabhängig. |
| #273 | Vitest 4.1.12 (Dependabot-Blocker) | Werkzeug | Unabhängig; CI grün laut PR. |

## 4. Neuer Befund aus dieser Durchsicht (statisch, nicht ausgeführt)

**`extractDisclosedClaimsStrict` (#288) akzeptiert nur flache Disclosures gegen das oberste `_sd`.**
Eine Disclosure, deren Digest in einem *verschachtelten* `_sd` liegt, wird abgelehnt
(`origin/fix/strict-disclosure-264:src/packages/shared-crypto/src/sd-jwt-vc.ts`, neue Funktion,
`allowed = new Set(sdDigests)` nur aus Top-Level).

Das ist **fail-closed und für den heutigen Pfad korrekt**. Aber: Das EUDI-PID-Profil als SD-JWT VC
kodiert das Alter laut der Juni-Recherche in #97 verschachtelt als `age_equal_or_over: { "18": true }`.
Würde die Vorlage dieses Profil wählen, würde ein echter PID mit #288 **abgelehnt** — rekursive
Disclosure-Prüfung (RFC 9901) wäre dann Pflichtarbeit. *Annahme:* Die Juni-Angabe zum PID-Schema
ist noch aktuell; vor Implementierung gegen die gewählte Rulebook-Version prüfen.

Zweite Beobachtung: Ein Disclosure-*Wert*, der selbst ein Objekt mit `_sd` enthält, wird als
undurchsichtiges Objekt übernommen, nicht aufgelöst. Für den aktiven Pfad folgenlos
(`active-profile.ts` verlangt `typeof age === 'number'`); für ein Boolean-Profil muss
`=== true` strikt geprüft werden.

## 5. Die eine Entscheidung, die vor Code fällt

Ohne sie ist der Weg **nicht** klar; jede Implementierung würde ein Profil stillschweigend festlegen,
was #97 ausdrücklich ausschließt.

| Option | Format / Claim | Was der Verifier sieht | Eigene Arbeit (aus Befunden) | Interop-Test möglich mit |
|---|---|---|---|---|
| **A. EU AV-Profil** | mdoc `eu.europa.ec.av.1`, `age_over_18` | Nur Boolean (Profil verbietet weitere Attribute, laut #97) | mdoc-DeviceAuth ist invertiert (`API-04`); DCQL/OID4VP 1.0 fehlt (`API-07`); mdoc-Pfad im aktiven Verifier fehlt | AV-Referenz-App / EUDI-Referenz-Wallet (zu prüfen) |
| **B. EUDI PID SD-JWT VC** | `urn:eudi:pid:1`, `age_equal_or_over.18` | Boolean, aber Credential trägt weitere selektiv offenlegbare PID-Daten | Rekursive Disclosures (§4); DCQL (`API-07`); `typ dc+sd-jwt` (`API-03`) | EUDI-Referenz-Wallets (Android/iOS) |
| **C. Eigenes flaches SD-JWT** | eigener VCT, `age_over_18: true` | Boolean | Kleinste Änderung (neues `active-profile`) | **Keine offizielle Wallet** — nur eigene |

**Bewertung (Wertung, nicht Fakt):**
- **C** ist technisch am nächsten, erfüllt aber das Ziel „kompatible Wallet" nicht. Nur als
  Zwischenschritt sinnvoll, um den Verifier-Vertrag (`eligible` ohne Alter) früh mit Negativtests
  zu fixieren — und nur, wenn klar als *nicht-offiziell* gekennzeichnet.
- **A** ist datenschutzseitig am stärksten und zweckgebaut, verlangt aber mdoc + DCQL.
- **B** hat die breiteste Wallet-Verfügbarkeit, aber das Credential ist ein PID — mehr Daten im
  Umlauf, auch wenn nur ein Boolean offengelegt wird.

**Build-vs-Reuse (kann ein kleiner Kreis eigene Protokoll- und Kryptografie-Implementierungen dauerhaft warten?):** Vor A oder B sollte geprüft werden, ob die offizielle Verifier-Komponente
(EUDI Web Verifier / Verifier-Endpoint) die Protokollschicht übernehmen kann und miTch nur den dünnen
Adapter „Verifier-Ergebnis → begrenztes Anwendungsergebnis" plus Policy liefert. Das würde
`API-03`, `API-04`, `API-07` aus der eigenen Wartungslast nehmen. *Offen:* Lizenz, Betriebsmodell,
Datenfluss dieser Komponente — nicht geprüft.

## 6. Vorgeschlagene Reihenfolge

1. **Merge der Voraussetzungen** (Owner-Entscheidung, Reviews ausstehend): #288, dann #276.
2. **Profil-Entscheidung** A / B / C(+später A oder B) und Build-vs-Reuse — schriftlich in #97.
3. **Verifier-Vertrag fixieren** (unabhängig vom Format):
   - Anwendung erhält nur `{ eligible: boolean, profile, decision_id }`.
   - Negativtests: falscher Aussteller, fremder `kid`, abgelaufen, widerrufen, falsche Nonce/`aud`,
     Replay, zusätzlicher Claim, numerisches Alter im Boolean-Profil, `age_over_18: "true"` (String),
     unsignierte Trust-/Status-Liste im `live`-Modus.
4. **Offene Vertrauenslücken im aktiven Pfad schließen:** Status-Listen-Signatur (`API-05`),
   JWKS-Auswahl per `kid` (#240-Rest).
5. **Erst dann** Interop-Test gegen eine offizielle Referenz-Wallet, mit Artefakt (Version, Commit,
   Request, Response, Ergebnis) als datierter `docs/qa/`-Eintrag.

## 6a. Stand 2026-11-18 (Nachtrag; §1–§6 bleiben unverändert)

| Schritt | Entscheidung / Stand | Nachweis |
|---|---|---|
| 2 | Owner wählt **Profil C** als nicht-offiziellen Zwischenschritt; A oder B bleibt Ziel (#97 offen). | Owner-Entscheidung im Chat, 2026-11-18 |
| 3 | Umgesetzt in #291: `{ eligible, profile }` an die Anwendung, 18 Negativtests mit echten Signaturen. **Kein `decision_id`** — der Verifier hat noch keinen Entscheidungsdatensatz. | [qa/AGE_OVER_18_EXPLORATION_PROFILE_2026-11-18.md](../qa/AGE_OVER_18_EXPLORATION_PROFILE_2026-11-18.md) (Branch von #291) |
| 4a | `kid`-Auswahl umgesetzt in #292. | [qa/ISSUER_KID_SELECTION_2026-11-18.md](../qa/ISSUER_KID_SELECTION_2026-11-18.md) (Branch von #292) |
| 4b | **Neuer Befund:** Ohne `status`-Claim wird Widerruf gar nicht geprüft (`oid4vp/src/demo-flow.ts:366`), und issuer-mock stellt keinen aus. Die Status-Liste ist zudem unsigniert (`API-05`). Owner-Entscheidung: **vorerst nur dokumentieren**; Optionen und Abnahmekriterien in #293. | #293 |

Folge für die Negativtests aus Schritt 3: „abgelaufen" und „widerrufen" sowie „unsignierte
Status-Liste" sind für Profil C **nicht** abgedeckt, solange #293 offen ist. Ein grüner
Profil-C-Test sagt nichts über Widerruf aus.

## 7. Was ausdrücklich nicht behauptet wird

- Keine Unverknüpfbarkeit: Auch ein Boolean ist über Credential-Signatur, Holder-Key (`cnf`),
  Netzwerk und Zeitpunkt korrelierbar. Ohne Batch-/Einmal-Credentials oder ZK bleibt das so.
- Keine EU-Konformität, kein Interop, kein Security-PASS.
- #287 und #289 sind Erkundung bzw. Modell, keine Freigabe der Vorlage.
