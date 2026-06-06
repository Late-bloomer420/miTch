# miTch MCP-Server — Architektur-Vorschlag v0.1

Stand: 2026-05-20. Status: Entwurf zur Diskussion.

## 1. Ziel

Die miTch-Policy-Engine als MCP-Server exponieren, sodass LLM-Agents (Claude
Desktop, Claude Code, Cowork, beliebige MCP-Clients) Disclosure-Anfragen
gegen eine miTch-Instanz prüfen können — ohne dass der Agent selbst Zugriff
auf Roh-Credentials, Schlüssel oder Audit-Daten erhält.

Konkret: ein Agent stellt eine strukturierte Anfrage ("Darf Verifier X
Claim Y vom Holder Z erhalten?"), miTch antwortet mit einer signierten
DecisionCapsule (`verdict ∈ {ALLOW, DENY, PROMPT}`, `decision_id`,
`policy_hash`, `reason_codes[]`). Der Agent erfährt nur das Verdikt plus
strukturierte Begründung — keine Rohdaten.

## 2. Warum MCP für miTch sinnvoll ist

- **Souveränität nach außen**: miTch wird vom internen Wallet-Modul zu einer
  Schnittstelle, die andere Agents *abfragen* können — ohne dass sie in das
  System hineingreifen. Klassische Trennung zwischen Anfrage-Layer und
  Daten-Layer.
- **Fail-closed als Default-Schutz für Agents**: Wenn ein LLM unklar
  formuliert, antwortet miTch DENY. Das macht den Server eine sichere
  Default-Senke für Disclosure-Logik in agentischen Workflows.
- **Zero-Knowledge-Ergonomie**: Predicates (`age-over-18`,
  `set-membership`) sind über Tools natürlich abbildbar — der Agent muss
  keine PII anfragen, sondern fragt nach Eigenschaften.
- **Attribut-/Nachweis-Logik statt Rohdaten** — passt zur miTch-Leitlinie.

## 3. Transport-Entscheidung — stdio für v1

| Kriterium | stdio (v1) | Streamable HTTP (v2) |
|---|---|---|
| Latenz | minimal | netzwerkabhängig |
| Auth-Komplexität | keine (lokaler Prozess) | OAuth/JWT/mTLS nötig |
| Datenfluss | im selben Trust-Boundary | überschreitet Boundary |
| Datenminimierung | maximal | erfordert Sorgfalt |
| Multi-Client | nein | ja |
| Reifegrad nötig | gering | mittel-hoch |

**Empfehlung v1**: stdio. Der Server läuft als Subprozess des MCP-Clients
(z. B. Claude Desktop) auf demselben Gerät wie der miTch-Wallet. Schlüssel,
Audit-Log und Storage bleiben lokal. Kein OAuth-Provider nötig.

**v2-Pfad**: Streamable HTTP für Remote-Verifier-Szenarien — mit
DPoP-/mTLS-gebundenen Tokens und expliziter Trust-Layer-Aushandlung. Erst
sinnvoll, wenn der externe Verifier-Pfad klar definiert ist.

## 4. Tool-Inventar (v1)

Naming-Konvention: `mitch_{verb}_{object}` (snake_case, Service-Prefix).

| Tool | Typ | Annotations | Zweck |
|---|---|---|---|
| `mitch_evaluate_disclosure` | core | `readOnlyHint: false`, `idempotentHint: true`, `destructiveHint: false`, `openWorldHint: false` | Verifier-Request + Policy + Context → DecisionCapsule. Kernroute. |
| `mitch_verify_presentation` | core | `readOnlyHint: true` | OID4VP-Response prüfen (Signatur, Nonce, Holder-Binding). Delegiert an `@askmi/oid4vp-verifier`. |
| `mitch_check_status` | core | `readOnlyHint: true` | Revocation/StatusList prüfen (`@askmi/revocation-statuslist`). |
| `mitch_list_policies` | read | `readOnlyHint: true` | Aktive Policy-Manifests + Hashes auflisten. |
| `mitch_get_policy` | read | `readOnlyHint: true` | Einzelne Policy nach `policy_hash` lesen. |
| `mitch_get_decision` | read | `readOnlyHint: true` | DecisionCapsule per `decision_id` aus Audit-Log holen. |
| `mitch_list_decisions` | read | `readOnlyHint: true` | Paginierte Liste vergangener Entscheidungen, mit Filter (Zeit/Verifier/Verdikt). |
| `mitch_explain_denial` | read | `readOnlyHint: true` | Reason-Codes → menschenlesbare Erklärung (i18n, DSGVO-tauglich). |
| `mitch_anchor_status` | read | `readOnlyHint: true` | Merkle-Anchor-Status zu einem `decision_id` (an `@askmi/anchor-service`). |

**Bewusst nicht exponiert (v1)**: alles, was Roh-Credentials oder
Schlüsselmaterial berührt. Keine `get_credential`, kein `sign_*`, kein
`export_*`. Falls Verifier später strukturierte Disclosure brauchen, geht
das über `evaluate_disclosure` + `verify_presentation` — der LLM-Agent
sieht nur Verdikte und signierte Aussagen.

## 5. Input-/Output-Schemas (Beispiel)

`mitch_evaluate_disclosure`:

```ts
// Input (Zod)
{
  verifier_request: {
    verifier_id: string,      // DID oder Origin
    requested_claims: string[],
    purpose: string,
    nonce: string,
  },
  context: {
    user_did: string,
    interaction?: InteractionMetadata,
    override_granted?: boolean,
  },
  policy_hash?: string,       // optional: spezifische Policy
  response_format?: "json" | "markdown",  // default json
}

// Output (structuredContent)
{
  verdict: "ALLOW" | "DENY" | "PROMPT",
  decision_id: string,        // UUID
  policy_hash: string,
  reason_codes: ReasonCode[],
  ...selectiveDisclosurePlan,  // bei ALLOW: Liste der freigegebenen Claims
  signed_capsule: string,     // base64url(Ed25519-Sig)
}
```

## 6. Sicherheit & Privacy

- **Eingaben validieren**: alle Inputs durch Zod-Schemas. `verifier_id`
  als DID/URL-Schema prüfen. Längen begrenzen.
- **Keine internen Fehler nach außen**: Stack-Traces nie an den Client.
  Fehler ausschließlich als strukturierte Reason-Codes
  (`ERR_LOGICAL_IMPOSSIBILITY`, `ERR_FUTURE_ISSUANCE`, …).
- **Audit-Trail bleibt lokal**: jeder Tool-Call wird im immutable Audit-Log
  (`@askmi/audit-log`) festgehalten, der Agent erhält nur die `decision_id`.
- **Rate-Limiting auf Tool-Ebene**: nutzt den vorhandenen Rate-Limiter aus
  `policy-engine/src/rate-limiter.ts`. Per-Agent + per-Verifier-Caps.
- **Kein stdout-Logging**: in stdio-Mode geht jedes Logging ausschließlich
  nach stderr — sonst wird das Protokoll korrumpiert.
- **Keine Roh-Credentials in der MCP-Antwort**: prinzipiell. Nur Verdikt,
  Reason-Codes, signiertes Capsule.

## 7. Package-Layout

Neues Workspace-Package gemäß miTch-Konvention:

```
src/packages/mcp-server/
├── package.json                # name: "@askmi/mcp-server", bin: "mitch-mcp"
├── tsconfig.json
├── src/
│   ├── index.ts                # Server-Entry: Transport + Tool-Registrierung
│   ├── tools/
│   │   ├── evaluate-disclosure.ts
│   │   ├── verify-presentation.ts
│   │   ├── check-status.ts
│   │   ├── list-policies.ts
│   │   ├── get-policy.ts
│   │   ├── get-decision.ts
│   │   ├── list-decisions.ts
│   │   ├── explain-denial.ts
│   │   └── anchor-status.ts
│   ├── schemas.ts              # Zod-Schemas, geteilt mit shared-types
│   ├── server.ts               # registerTool-Aufrufe, Annotations
│   ├── errors.ts               # MCP-konforme Fehlerabbildung
│   └── __tests__/
│       └── tools.test.ts       # Vitest, environment: node
└── README.md
```

Dependencies (extern):
- `@modelcontextprotocol/sdk` (TypeScript-SDK)
- `zod` (für Input-Schemas)

Dependencies (intern, workspace:*):
- `@askmi/policy-engine`
- `@askmi/oid4vp-verifier`
- `@askmi/revocation-statuslist`
- `@askmi/audit-log`
- `@askmi/shared-types`
- `@askmi/anchor-service` (optional, für `anchor_status`)

## 8. Test- und Release-Strategie

- **Unit**: Vitest in `src/__tests__/`, pro Tool ein Test-File. Snapshot-
  Tests für die Output-Struktur der DecisionCapsule.
- **Integration**: Ein E2E-Test, der die echte Policy-Engine über das
  MCP-Tool ansteuert (kein Mocking). Läuft in derselben Vitest-Pipeline.
- **MCP-Inspector**: `npx @modelcontextprotocol/inspector dist/index.js`
  zum manuellen Smoke-Test.
- **CI**: an die vorhandene Pipeline anhängen (`pnpm build`, `pnpm test`,
  `pnpm lint`). Layer-Validation-Job sollte den MCP-Tool-Pfad mit
  abdecken.
- **Versionierung**: Conventional Commits, semver. Public API ist die
  Tool-Liste — kein Tool umbenennen ohne Major-Bump.

## 9. Offene Fragen (für dich zu entscheiden)

1. **Soll `evaluate_disclosure` synchron oder asynchron arbeiten?**
   Für PROMPT-Verdikte muss ein User-Consent eingeholt werden. Optionen:
   (a) MCP-Tool gibt PROMPT sofort zurück, Agent fragt User-Consent
   außerhalb an, ruft erneut mit `override_granted` auf;
   (b) Server hält Long-Polling. — Empfehlung: (a), ist sauberer und
   passt zu stateless stdio.

2. **Wie wird die Wallet-Instanz lokalisiert?**
   Über Env-Variable (`MITCH_WALLET_DB=/path/...`), oder soll der Server
   einen festen Pfad annehmen? — Empfehlung: Env-Variable, mit Fallback
   auf `~/.mitch/wallet.db`.

3. **Brauchen wir `mitch_get_decision` öffentlich, oder bleibt das
   internes Wallet-Tool?** Wenn externe Verifier Audit-Belege brauchen,
   ja — aber dann mit Pairwise-DID-Scoping, damit nur der Verifier seine
   eigenen Decisions sieht.

4. **Erste Zielgruppe — entschieden 2026-05-21**: Compliance-Auditor-LLM
   (lokal lauffähig). Begründung: Ein lokales Modell wertet
   Decision-Logs aus, Ergebnisse bleiben on-device, Daten können bei
   Bedarf gelöscht werden — kein Datenabfluss nach außen. Das macht das
   primäre Tool-Inventar zu den Read-Tools (`mitch_get_decision`,
   `mitch_list_decisions`, `mitch_explain_denial`), nicht zu
   `mitch_evaluate_disclosure`. Distribution: npm-Paket reicht, kein
   DXT-Bundle nötig (lokale Modelle laufen meist über eigenen Stack).

## 10. Nächste konkrete Schritte

1. Diesen Vorschlag durchgehen, Änderungen einkippen.
2. Package-Skelett anlegen (Task #9): `pnpm create` + tsconfig + initiale
   Stub-Tools (return DENY mit Reason `NOT_IMPLEMENTED`).
3. **Stub-Phase eingefroren** (Stand 2026-05-21): `mitch_evaluate_disclosure`
   bleibt vorerst DENY-Stub. Wiring blockiert auf erste Anwender-Story —
   siehe §9.4. Begründung: ohne konkreten Konsumenten ist die
   Policy-Quellen-Frage (embedded vs. file vs. agent-supplied) nicht
   sauber zu entscheiden, und ein embedded Default produziert echte
   Decisions ohne autorisierte Policy.
4. **Read-Tools ebenfalls eingefroren — Stand 2026-05-22**: Auch
   `mitch_list_decisions`, `mitch_get_decision`, `mitch_explain_denial`
   bleiben unimplementiert, bis ein konkreter Anwendungsfall steht.
   Gating-Frage: was leistet der MCP-Server, was ein lokales LLM mit der
   exportierten `AuditLogExport.json` als File-Input nicht selbst kann?
   Vermutete Mehrwerte (strukturierte Tool-Calls statt Freitext-Parsing,
   Reason-Code-Anreicherung, Hash-Chain-Verifikation) brauchen einen
   echten Bedarf — sonst ist der einfachere Pfad „Wallet-Export →
   LLM-Chat mit JSON" überlegen.
5. **Trigger zum Auftauen**: konkrete User-Story mit Mengen-/Frequenz-
   Schätzung. Insbesondere wenn (a) Audit-Logs > ~10k Entries werden und
   Token-Effizienz zählt, (b) Reports an externe Dritte gehen und
   Hash-Chain-Verifikation ein Verkaufsargument ist, oder (c) eine
   wiederkehrende Audit-Routine entsteht, die strukturierte Queries
   braucht. Bis dahin: nichts bauen, Stub-Disziplin halten.
6. Inspector-Smoke-Test, sobald irgendein Tool wirklich implementiert
   wird.

## 11. Auftau-Entscheidung — `evaluate_disclosure` verdrahtet (2026-06-06)

Status: **aufgetaut**. Die in §10.3 eingefrorene Stub-Phase für
`askmi_evaluate_disclosure` wird hiermit bewusst beendet.

**Auftau-Trigger (gemäß §10.5):** die konkrete Anwender-Story ist die
agentische MCP-Integration selbst (Epic 5 / CI-01): ein LLM-Agent soll die
AskMI-PolicyEngine abfragen können, *ob* eine Disclosure erlaubt wäre, ohne
Zugriff auf Daten zu erhalten. Das ist der in §10.5 geforderte konkrete
Konsument.

**Wie das ursprüngliche Bedenken gewahrt bleibt** (§10.3: „ein embedded
Default produziert echte Decisions ohne autorisierte Policy"):

- Die Engine läuft echt, aber gegen einen **explizit als Mock gekennzeichneten
  Scope** (`src/server-scope.ts`): synthetische Policy **und** synthetische
  Credential-Metadaten. Nichts davon ist autoritativ.
- Jede Tool-Antwort trägt `scope: "mock"`. Kein Konsument kann eine
  Mock-Entscheidung mit einer echten Wallet-Decision verwechseln.
- Es wird **keine** stille embedded Default-Policy aktiviert. Der Pfad zu einer
  echten, autorisierten Policy (Env `MITCH_WALLET_DB`, §9.2) bleibt offen und
  unverändert; er ersetzt später nur `server-scope.ts`, der Tool-Vertrag bleibt
  gleich.

**Controlled-Insight-Grenze** (`src/sanitize.ts`): Das reichhaltige
`PolicyEvaluationResult` wird auf ein Whitelist-Objekt reduziert
(`verdict`, `decision_id`, `policy_hash`, `reason_codes`, `disclosed_claims`,
`proven_claims`, `scope`, `evaluated_at`). Bewusst **nicht** exponiert:
`selected_credential_id`, `issuer_trust_refs`, `request_hash`,
`wallet_attestation`, `pairwise_did`, `authorized_requirements`, die
Credential-IDs und Issuer-DIDs. Der Sanitizer spreadet das Engine-Resultat
nie — ein künftig hinzugefügtes (evtl. sensibles) Feld kann nicht versehentlich
durchsickern. Abgesichert durch den Leak-Test in
`__tests__/evaluate-disclosure.test.ts`.

**Verdikt-Matrix des Mock-Scopes** (deterministisch, für Tests):

| Verifier | Ergebnis | Grund |
|---|---|---|
| `did:web:liquor-store.example.com` | ALLOW | Regel matcht, vertrauenswürdiger Issuer, kein Consent-Gate |
| `did:web:hospital.example.com` | PROMPT | Regel matcht, `requiresUserConsent` |
| sonst | DENY | `blockUnknownVerifiers` (fail-closed) |

**Noch eingefroren:** Die Read-Tools (`mitch_get_decision`,
`mitch_list_decisions`, `mitch_explain_denial`) bleiben gemäß §10.4
unimplementiert, bis die in §10.5 genannte Audit-Story steht. Nur
`evaluate_disclosure` ist aufgetaut.

## 12. Lokaler Evaluation-Scope via `MITCH_WALLET_DB` (2026-06-06)

Status: **teilweise aufgetaut**. `evaluate_disclosure` bleibt standardmäßig im
Mock-Scope, kann aber explizit mit einem lokalen Evaluation-Scope betrieben
werden.

`src/evaluation-scope.ts` lädt bei gesetztem `MITCH_WALLET_DB` eine lokale
JSON-Datei mit:

- `policy`: `PolicyManifest`
- `credentials`: `StoredCredentialMetadata[]`
- optional `user_did` / `userDid`

Wichtig: Das ist **noch kein Wallet-DB-Adapter** und keine Roh-Credential-
Anbindung. Es werden ausschließlich Policy und Credential-Metadaten geladen.
Roh-VCs, Claim-Werte, Schlüssel, Signaturen und Proof-Material bleiben außerhalb
des MCP-Servers.

Sicherheitsverhalten:

- Ohne `MITCH_WALLET_DB`: Mock-Scope, Antwort `scope: "mock"`.
- Mit gültigem `MITCH_WALLET_DB`: lokaler Scope, Antwort `scope: "local"`.
- Mit ungültigem oder nicht lesbarem `MITCH_WALLET_DB`: fail-closed `DENY`,
  Antwort `scope: "local"`, keine disclosed/proven claims, kein stiller Fallback
  auf Mock.

Damit ist der Pfad aus §9.2 operationalisiert, ohne das ursprüngliche Freeze-
Bedenken zu verletzen: Eine echte Entscheidung kann nur entstehen, wenn der
Operator explizit eine lokale, autorisierte Scope-Datei konfiguriert.
