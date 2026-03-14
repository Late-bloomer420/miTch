# docs/specs — Status Index

**Date:** 2026-03-14
**Purpose:** Zentrale Statusübersicht aller 112 Spec-Dateien. Klassifizierung auf Basis von STATE.md, DOCS_CANON.md, REFACTORING_ROADMAP.md, 105_Visual_Control_Panel.md und belegbarem Repo-Stand.

---

## Statuskategorien

| Status | Bedeutung |
|--------|-----------|
| **ACTIVE REFERENCE** | Maßgebliche Spec für ihr Thema, noch aktuell |
| **IMPLEMENTED** | Kernidee im Code umgesetzt; Spec hat Design-Kontextwert |
| **PARTIALLY STALE** | Teils veraltet, teils noch nützlich |
| **ARCHIVE CANDIDATE** | Vollständig ersetzt, kein aktiver Referenzwert |
| **NEEDS REVIEW** | Einordnung unklar, manuelle Prüfung nötig |

---

## Zusammenfassung

| Status | Anzahl |
|--------|--------|
| ACTIVE REFERENCE | 25 |
| IMPLEMENTED | 35 |
| PARTIALLY STALE | 34 |
| ARCHIVE CANDIDATE | 17 |
| NEEDS REVIEW | 1 |
| **Gesamt** | **112** |

---

## Foundational (00-10)

| # | Datei | Titel | Status | Begründung | Evidenz |
|---|-------|-------|--------|------------|---------|
| 00 | 00_README.md | Context Pack README | PARTIALLY STALE | Dateiliste endet bei ~102, fehlt 103-112 | Datei selbst |
| 01 | 01_Project_OnePager.md | Project OnePager | ACTIVE REFERENCE | Kern-Positionierung, aktuell | STATE.md Pilot path |
| 02 | 02_Principles_and_NonNegotiables.md | Principles & Non-Negotiables | ACTIVE REFERENCE | Bindende Invarianten | Spec Inhalt |
| 03 | 03_Architecture_Core.md | Architecture Core | PARTIALLY STALE | Konzeptionell; tatsächliche Arch hat 24 Packages | STATE.md vs. Spec |
| 04 | 04_Data_Flows_and_PII_Boundaries.md | Data Flows & PII Boundaries | ACTIVE REFERENCE | PII-Grenzen weiterhin bindend | Spec Inhalt |
| 05 | 05_Threat_Model.md | Threat Model | ACTIVE REFERENCE | Grundlegend, weiterhin referenziert | Spec Inhalt |
| 06 | 06_Policy_Engine_Spec.md | Policy Engine Spec | PARTIALLY STALE | Phase 0 Spec; engine.ts deutlich weiterentwickelt | STATE.md Session 3+ |
| 07 | 07_Backlog_and_Roadmap.md | Backlog & Roadmap | ARCHIVE CANDIDATE | 2026-02-12; ersetzt durch STATE.md + REFACTORING_ROADMAP | STATE.md |
| 08 | 08_Prompts_for_Collaboration.md | Prompts for Collaboration | PARTIALLY STALE | AI-Prompts; Repo hat jetzt CLAUDE.md/MEMORY | Repo-Vergleich |
| 09 | 09_Glossary.md | Glossary | ACTIVE REFERENCE | Begriffsdefinitionen weiterhin nützlich | Spec Inhalt |
| 10 | 10_Open_Questions.md | Open Questions | ARCHIVE CANDIDATE | Frühe Planungsfragen, großteils gelöst | STATE.md Gaps closed |

## MVP Planning (11-30) — alle 2026-02-11

| # | Datei | Titel | Status | Begründung | Evidenz |
|---|-------|-------|--------|------------|---------|
| 11 | 11_MVP_Gap_Analysis.md | MVP Gap Analysis | ARCHIVE CANDIDATE | Alle Gaps geschlossen | STATE.md P0/P1 closed |
| 12 | 12_MVP_Execution_Plan_6_Weeks.md | MVP Execution Plan | ARCHIVE CANDIDATE | Ausführung abgeschlossen | STATE.md |
| 13 | 13_MVP_Readiness_Checklist.md | MVP Readiness Checklist | PARTIALLY STALE | Template hat Restwert für künftige Pilots | Template-Charakter |
| 14 | 14_MVP_Risk_Register.md | MVP Risk Register | ARCHIVE CANDIDATE | Ersetzt durch SPRINT_PLAN Findings | SPRINT_PLAN.md |
| 15 | 15_MVP_Work_Breakdown.md | MVP Work Breakdown | ARCHIVE CANDIDATE | Arbeit abgeschlossen | STATE.md 39/39 |
| 16 | 16_MVP_Architecture_Decision_Log.md | MVP Architecture Decision Log | PARTIALLY STALE | ADR-Index; siehe auch docs/compliance/ADR/ | docs/compliance/ADR/ |
| 17 | 17_API_Contract_v0.md | API Contract v0 | PARTIALLY STALE | Früher Entwurf; API hat sich entwickelt | Repo-Vergleich |
| 18 | 18_Test_Plan_Adversarial_and_E2E.md | Test Plan Adversarial & E2E | PARTIALLY STALE | Strategie relevant, Details veraltet | STATE.md Tests |
| 19 | 19_Data_Retention_Matrix.md | Data Retention Matrix | ACTIVE REFERENCE | Retention-Policy weiterhin bindend | Spec Inhalt |
| 20 | 20_Canonicalization_and_Binding_Spec_v0.md | Canonicalization & Binding | IMPLEMENTED | presentation-binding.ts existiert | src/packages/shared-crypto/ |
| 21 | 21_Deny_Reason_Code_Catalog.md | Deny Reason Code Catalog | ACTIVE REFERENCE | Normative Deny-Codes, aktiv referenziert | engine.ts |
| 22 | 22_Pilot_Go_NoGo_Template.md | Pilot Go/No-Go Template | ACTIVE REFERENCE | Template für Pilot-Entscheidung | 105 Pilot closure |
| 23 | 23_Implementation_Sequence_v0.md | Implementation Sequence | ARCHIVE CANDIDATE | Build-Reihenfolge abgearbeitet | STATE.md |
| 24 | 24_Repo_Setup_and_GitHub_Linking.md | Repo Setup & GitHub Linking | ARCHIVE CANDIDATE | Repo-Setup erledigt | Repo existiert |
| 25 | 25_Sprint_1_Task_Board.md | Sprint 1 Task Board | ARCHIVE CANDIDATE | Sprint 1 abgeschlossen | STATE.md |
| 26 | 26_Repository_Hygiene_Plan.md | Repository Hygiene Plan | ARCHIVE CANDIDATE | Cleanup erledigt | STATE.md Session 7 |
| 27 | 27_ADR_Closure_Record.md | ADR Closure Record | PARTIALLY STALE | MVP-ADRs; aktuell in docs/compliance/ADR/ | docs/compliance/ADR/ |
| 28 | 28_Test_Vector_Pack_v0.md | Test Vector Pack | PARTIALLY STALE | Normative Vektoren, mglw. noch Referenzwert | Spec Inhalt |
| 29 | 29_Implementation_Scaffold.md | Implementation Scaffold | ARCHIVE CANDIDATE | Scaffold gebaut | src/ packages |
| 30 | 30_First_Code_Tasks.md | First Code Tasks | ARCHIVE CANDIDATE | Tasks abgeschlossen | STATE.md |

## Business & Strategy (31-50)

| # | Datei | Titel | Status | Begründung | Evidenz |
|---|-------|-------|--------|------------|---------|
| 31 | 31_Interface_Definitions_v0.md | Interface Definitions v0 | ARCHIVE CANDIDATE | Frühe Interfaces; aktuelle Typen in shared-types | src/packages/shared-types/ |
| 32 | 32_Config_Profile_v0.md | Config Profile v0 | IMPLEMENTED | config-profiles.ts existiert | src/packages/policy-engine/ |
| 33 | 33_Business_Case_01_Age_Verification.md | Business Case Age Verification | ACTIVE REFERENCE | Kern-Pilot-Use-Case | 105 Pilot closure |
| 34 | 34_Use_Case_Prioritization_Matrix.md | Use Case Prioritization Matrix | ACTIVE REFERENCE | Leitet Scope-Entscheidungen | Spec Inhalt |
| 35 | 35_Product_Architecture_Layers.md | Product Architecture Layers | PARTIALLY STALE | Core/Shield/Orchestrator-Konzept; tatsächlich Packages | Repo-Vergleich |
| 36 | 36_Phase2_Shield_and_AI_Orchestration_Roadmap.md | Phase 2 Shield & AI Roadmap | PARTIALLY STALE | Zukunfts-Roadmap, noch nicht relevant | 105 DEFER |
| 37 | 37_Privacy_Policy_Language_for_Web_and_AI.md | Privacy Policy Language | PARTIALLY STALE | Nur Konzept, nicht implementiert | Repo-Vergleich |
| 38 | 38_KPI_Framework_Core_and_Business.md | KPI Framework Core & Business | ACTIVE REFERENCE | KPI-Design-Autorität | kpi.ts |
| 39 | 39_Pilot_KPI_Dashboard_Template.md | Pilot KPI Dashboard Template | ACTIVE REFERENCE | Template für Pilot-Ops | Spec Inhalt |
| 40 | 40_KPI_Definitions_and_Data_Sources.md | KPI Definitions & Data Sources | ACTIVE REFERENCE | Formeln und Ownership | Spec Inhalt |
| 41 | 41_Localhost_Test_Quickstart.md | Localhost Test Quickstart | PARTIALLY STALE | Ggf. Update nötig für aktuellen pnpm dev Flow | Repo-Vergleich |
| 42 | 42_Pilot_Critical_Config.md | Pilot Critical Config | ACTIVE REFERENCE | Erforderliche Env-Konfiguration | Spec Inhalt |
| 43 | 43_Pilot_Next_Steps_Plan.md | Pilot Next Steps Plan | PARTIALLY STALE | Teils erledigt, teils noch relevant | STATE.md |
| 44 | 44_Evidence_Runbook.md | Evidence Runbook | PARTIALLY STALE | Prozess relevant, aber `npm run evidence` Befehle veraltet (pnpm) | DOCS_CANON.md + Repo-Vergleich |
| 45 | 45_Adjudication_Workflow.md | Adjudication Workflow | PARTIALLY STALE | Konzept relevant, aber `npm run adjudicate` Befehle veraltet (pnpm) | Spec Inhalt + Repo-Vergleich |
| 46 | 46_Security_Attack_Testing.md | Security Attack Testing | ACTIVE REFERENCE | Adversarial Testing Scope | Spec Inhalt |
| 47 | 47_Risk_Register_Extended_Human_and_Governance.md | Risk Register Extended | PARTIALLY STALE | Einige Risiken mitigiert | STATE.md Findings closed |
| 48 | 48_Mitigations_ProofFatigue_PolicyTamper_Recovery_GDPR.md | Mitigations ProofFatigue etc. | IMPLEMENTED | proof-fatigue.ts, recovery.ts | src/packages/policy-engine/ |
| 49 | 49_Agentic_Threat_Model_and_Controls.md | Agentic Threat Model | ACTIVE REFERENCE | AI-Agent-Bedrohungsmodell | Spec Inhalt |
| 50 | 50_AI_Agent_Governance_Policy.md | AI Agent Governance Policy | ACTIVE REFERENCE | Governance-Baseline | Spec Inhalt |

## Security Hardening (51-60)

| # | Datei | Titel | Status | Begründung | Evidenz |
|---|-------|-------|--------|------------|---------|
| 51 | 51_RP_Onboarding_Pack.md | RP Onboarding Pack | ACTIVE REFERENCE | Pilot-Onboarding-Essentials | 105 Pilot closure |
| 52 | 52_RP_First_Success_Examples.md | RP First Success Examples | PARTIALLY STALE | Beispiele nützlich, aber PowerShell/npm-Befehle veraltet | Spec Inhalt + Repo-Vergleich |
| 53 | 53_TEE_Readiness_Gap.md | TEE Readiness Gap | ACTIVE REFERENCE | Gap-Analyse, T-31 offen | REFACTORING_ROADMAP TEE |
| 54 | 54_External_Security_Findings_Integration.md | External Security Findings | PARTIALLY STALE | Aktionsplan teilweise abgearbeitet | STATE.md Findings |
| 55 | 55_External_Findings_Expanded_Systemic_Risks.md | External Findings Expanded | PARTIALLY STALE | Einige Findings adressiert | STATE.md |
| 56 | 56_Risk_to_Roadmap_Mapping.md | Risk to Roadmap Mapping | PARTIALLY STALE | Teils gemappt, teils erledigt | STATE.md |
| 57 | 57_Proof_Fatigue_Control_v1.md | Proof Fatigue Control v1 | IMPLEMENTED | proof-fatigue.ts | src/packages/policy-engine/ |
| 58 | 58_Revocation_Baseline_v1.md | Revocation Baseline v1 | IMPLEMENTED | multi-source.ts, Bitstring-Utils | src/packages/revocation-statuslist/ |
| 59 | 59_Supply_Chain_Hardening_v1.md | Supply Chain Hardening v1 | ACTIVE REFERENCE | Fortlaufendes Thema | Spec Inhalt |
| 60 | 60_Legal_and_Jurisdiction_Security_Strategy.md | Legal & Jurisdiction Strategy | ACTIVE REFERENCE | Jurisdiktionsstrategie | Spec Inhalt |

## Hardening Series (61-102)

| # | Datei | Titel | Status | Begründung | Evidenz |
|---|-------|-------|--------|------------|---------|
| 61 | 61_Jurisdiction_Compatibility_Gate_v1.md | Jurisdiction Compatibility Gate | IMPLEMENTED | jurisdiction.ts | src/packages/policy-engine/ |
| 62 | 62_Revocation_Status_Resolver_v2_Scaffold.md | Revocation Status Resolver v2 | IMPLEMENTED | multi-source.ts | src/packages/revocation-statuslist/ |
| 63 | 63_Deny_Code_Credential_Revoked.md | Deny Code Credential Revoked | IMPLEMENTED | Deny-Codes in engine.ts | src/packages/policy-engine/ |
| 64 | 64_Deny_Code_Status_Source_Unavailable.md | Deny Code Status Source Unavailable | IMPLEMENTED | Deny-Codes in engine.ts | src/packages/policy-engine/ |
| 65 | 65_KPI_Deny_Category_Visibility.md | KPI Deny Category Visibility | IMPLEMENTED | kpi.ts | src/packages/policy-engine/ |
| 66 | 66_Dashboard_Security_KPI_Box.md | Dashboard Security KPI Box | PARTIALLY STALE | KPI-Engine existiert, Dashboard-UI nicht gebaut | kpi.ts vs. fehlende UI |
| 67 | 67_Strong_ReAuth_Scaffold_v1.md | Strong ReAuth Scaffold | IMPLEMENTED | step-up-auth.ts | src/packages/webauthn-verifier/ |
| 68 | 68_StatusList2021_Input_Shape_Scaffold.md | StatusList2021 Input Shape | IMPLEMENTED | revocation-statuslist Types | src/packages/revocation-statuslist/ |
| 69 | 69_StatusList2021_Index_Check_Light.md | StatusList2021 Index Check | IMPLEMENTED | Bitstring-Utils | src/packages/revocation-statuslist/ |
| 70 | 70_Status_Source_Response_Hardening.md | Status Source Response Hardening | IMPLEMENTED | Multi-Source-Resolver | src/packages/revocation-statuslist/ |
| 71 | 71_Revoked_Only_Cache_Safety_Model.md | Revoked-Only Cache Safety | PARTIALLY STALE | Design-Spec, Cache nicht vollständig gebaut | Spec vs. Repo |
| 72 | 72_KPI_Revoked_Cache_Observability.md | KPI Revoked Cache Observability | PARTIALLY STALE | KPI-Engine existiert, Cache-KPIs nicht verdrahtet | kpi.ts vs. Spec |
| 73 | 73_Dashboard_Revoked_Cache_KPI.md | Dashboard Revoked Cache KPI | PARTIALLY STALE | Dashboard-UI nicht gebaut | fehlende UI |
| 74 | 74_Security_KPI_Alert_Thresholds_v1.md | Security KPI Alert Thresholds | IMPLEMENTED | kpi.ts Alert-Schwellenwerte | src/packages/policy-engine/ |
| 75 | 75_KPI_Check_SoftFail_Mode.md | KPI Check SoftFail Mode | IMPLEMENTED | kpi.ts Soft-Fail-Modus | src/packages/policy-engine/ |
| 76 | 76_Strict_Profile_Example.md | Strict Profile Example | IMPLEMENTED | config-profiles.ts strict | src/packages/policy-engine/ |
| 77 | 77_StatusList_Reference_Validation_v3_Light.md | StatusList Reference Validation | IMPLEMENTED | Multi-Source-Resolver | src/packages/revocation-statuslist/ |
| 78 | 78_WebAuthn_Strong_ReAuth_Window_v2.md | WebAuthn Strong ReAuth Window | IMPLEMENTED | step-up-auth.ts | src/packages/webauthn-verifier/ |
| 79 | 79_WebAuthn_Challenge_Replay_Protection.md | WebAuthn Challenge Replay Protection | IMPLEMENTED | step-up-auth.ts | src/packages/webauthn-verifier/ |
| 80 | 80_WebAuthn_RPID_Origin_Binding_v3.md | WebAuthn RPID Origin Binding | IMPLEMENTED | webauthn-verifier | src/packages/webauthn-verifier/ |
| 81 | 81_KPI_WebAuthn_Drift_Visibility.md | KPI WebAuthn Drift Visibility | PARTIALLY STALE | KPI-Felder existieren, Dashboard nicht verdrahtet | kpi.ts vs. Spec |
| 82 | 82_DID_Resolver_Hardening_v1_Scaffold.md | DID Resolver Hardening Scaffold | IMPLEMENTED | did-quorum.ts | src/packages/shared-crypto/ |
| 83 | 83_DID_Resolver_Config_Profile_v1.md | DID Resolver Config Profile | IMPLEMENTED | QUORUM_PROFILES | src/packages/shared-crypto/ |
| 84 | 84_DID_Resolver_Quorum_Logic_v1.md | DID Resolver Quorum Logic | IMPLEMENTED | QuorumDIDResolver | src/packages/shared-crypto/ |
| 85 | 85_Resolver_Inconsistency_Observability_v1.md | Resolver Inconsistency Observability | IMPLEMENTED | Quorum-Inkonsistenz-Erkennung | src/packages/shared-crypto/ |
| 86 | 86_KPI_Resolver_Inconsistency_Alerts.md | KPI Resolver Inconsistency Alerts | PARTIALLY STALE | Erkennung existiert, Alerting nicht verdrahtet | did-quorum.ts vs. Spec |
| 87 | 87_KPI_Resolver_Quorum_Failure_Alerts.md | KPI Resolver Quorum Failure Alerts | PARTIALLY STALE | Erkennung existiert, Alerting nicht verdrahtet | did-quorum.ts vs. Spec |
| 88 | 88_Deny_Code_Resolver_Quorum_Failed.md | Deny Code Resolver Quorum Failed | IMPLEMENTED | Deny-Codes in engine.ts | src/packages/policy-engine/ |
| 89 | 89_KPI_Deny_Resolver_Quorum_Failed_Alerts.md | KPI Deny Resolver Quorum Failed | PARTIALLY STALE | KPI-Felder existieren, Alerting nicht verdrahtet | kpi.ts vs. Spec |
| 90 | 90_No_Silent_Allow_Assertion.md | No Silent Allow Assertion | IMPLEMENTED | allow-assertion.ts | src/packages/policy-engine/ |
| 91 | 91_Trust_Guardrail_False_Allow_Zero_Tolerance.md | Trust Guardrail False-Allow Zero | IMPLEMENTED | allow-assertion.ts | src/packages/policy-engine/ |
| 92 | 92_Cost_KPI_Estimation_v1.md | Cost KPI Estimation | IMPLEMENTED | kpi.ts Kostenberechnung | src/packages/policy-engine/ |
| 93 | 93_PQ_Readiness_Crypto_Agility_v1.md | PQ Readiness Crypto Agility | IMPLEMENTED | crypto-agility.ts, pqc.ts | src/packages/shared-crypto/ |
| 94 | 94_WebAuthn_Crypto_Verification_Scaffold_v3.md | WebAuthn Crypto Verification Scaffold | NEEDS REVIEW | Scaffold-Konzept, Umsetzungsgrad unklar | Manuelle Prüfung nötig |
| 95 | 95_WebAuthn_Native_Verifier_Hook_v1.md | WebAuthn Native Verifier Hook | IMPLEMENTED | webauthn-verifier Modul mit step-up-auth.ts, verifier.ts | src/packages/webauthn-verifier/ |
| 96 | 96_WebAuthn_Native_Hook_Bound_Adapter_Evidence.md | WebAuthn Native Hook Bound Adapter | PARTIALLY STALE | Konzept, nicht vollständig gebaut | Spec vs. Repo |
| 97 | 97_WebAuthn_Config_Health_Guardrail.md | WebAuthn Config Health Guardrail | PARTIALLY STALE | Konzept, nicht vollständig verdrahtet | Spec vs. Repo |
| 98 | 98_WebAuthn_Native_Mode_Usage_Visibility.md | WebAuthn Native Mode Usage Visibility | PARTIALLY STALE | Konzept, nicht vollständig verdrahtet | Spec vs. Repo |
| 99 | 99_WebAuthn_Allowlist_Mode_Drift_Warning.md | WebAuthn Allowlist Mode Drift Warning | PARTIALLY STALE | Konzept, nicht vollständig verdrahtet | Spec vs. Repo |
| 100 | 100_Security_Profile_Score_KPI_v1.md | Security Profile Score KPI | IMPLEMENTED | kpi.ts computeSecurityScore() | src/packages/policy-engine/ |
| 101 | 101_WebAuthn_Native_Runtime_Usage_Metrics.md | WebAuthn Native Runtime Usage Metrics | PARTIALLY STALE | Metriken-Konzept, nicht vollständig verdrahtet | Spec vs. Repo |
| 102 | 102_WebAuthn_Mismatch_and_Replay_Edge_Tests.md | WebAuthn Mismatch & Replay Edge Tests | PARTIALLY STALE | Test-Spec, teilweise abgedeckt | Spec vs. Tests |

## Meta & Strategic (103-112)

| # | Datei | Titel | Status | Begründung | Evidenz |
|---|-------|-------|--------|------------|---------|
| 103 | 103_GTM_Security_Decision_Framework.md | GTM Security Decision Framework | ACTIVE REFERENCE | Entscheidungs-Template | 105 Decision Gates |
| 104 | 104_Decision_Card_Example_ZK_Bundle_v2.md | Decision Card Example ZK Bundle | ACTIVE REFERENCE | Gearbeitetes Beispiel zu 103 | 103 Referenz |
| 105 | 105_Visual_Control_Panel.md | Visual Control Panel | ACTIVE REFERENCE | NOW/NEXT/LATER/DEFER Leitdokument | STATE.md |
| 106 | 106_Document_Map_By_Purpose.md | Document Map By Purpose | PARTIALLY STALE | Fehlt 107-112, braucht Update | Datei selbst |
| 107 | 107_Positioning_Guardrail_Not_WorldCoin2.md | Positioning Guardrail | ACTIVE REFERENCE | Narrative Guardrail | 105 Positioning |
| 108 | 108_Policy_Conflict_Resolution_and_Anti_Oracle.md | Policy Conflict Resolution | PARTIALLY STALE | engine.ts hat Konfliktbehandlung, aber Spec ist als DRAFT markiert | src/packages/policy-engine/ + Spec DRAFT |
| 109 | 109_Presentation_Binding_AntiReplay_Spec_v1.md | Presentation Binding AntiReplay | IMPLEMENTED | presentation-binding.ts | src/packages/shared-crypto/ |
| 110 | 110_eID_Issuer_Simulator_Fidelity.md | eID Issuer Simulator Fidelity | ACTIVE REFERENCE | Simulator-Constraints | Spec Inhalt |
| 111 | 111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md | Unlinkability Phase 1 Pairwise DIDs | IMPLEMENTED | pairwise-did.ts | src/packages/shared-crypto/ |
| 112 | 112_Component_Isolation_Model.md | Component Isolation Model | ACTIVE REFERENCE | Isolations-Design | Spec Inhalt |

---

## Priorisierung (basierend auf 105_Visual_Control_Panel.md)

### Aktiv wichtig (NOW / NEXT)
- **01, 02, 04, 05**: Kern-Prinzipien und Bedrohungsmodell
- **19, 21, 22**: Retention, Deny-Codes, Go/No-Go
- **33, 38-40, 42, 46**: Business Case, KPIs, Pilot-Config, Adversarial Testing
- **49-51, 53, 59-60**: Governance, Onboarding, TEE Gap, Supply Chain, Jurisdiktion
- **103, 105, 107, 110, 112**: Entscheidungsrahmen, Control Panel, Positionierung, Simulator, Isolation

### Umgesetzt (historischer Kontext)
35 Specs beschreiben Konzepte, die im Code leben. Sie haben Design-Kontextwert, aber die Implementation ist die Wahrheitsquelle:
- 20, 32, 48, 57-58, 61-65, 67-70, 74-80, 82-85, 88, 90-93, 95, 100, 109, 111

### Nur noch Archivwert
17 Specs sind reine Planungs-Artefakte ohne aktiven Referenzwert:
- 07, 10-12, 14-15, 23-26, 29-31

### Nächste Kandidaten für Arbeit
Basierend auf 105 (NOW/NEXT) und dem PARTIALLY STALE Status:
1. **WebAuthn Native Verifier (94, 96-102)**: Größter Block PARTIALLY STALE Specs — Umsetzungsgrad klären
2. **Dashboard/Alerting-Verdrahtung (66, 72-73, 81, 86-87, 89)**: KPI-Engine existiert, UI/Alerting fehlt
3. **Cache-Safety (71)**: Revoked-Only-Cache ist Design-Spec ohne vollständige Implementation
4. **00_README.md Update**: Dateiliste auf 112 Specs vervollständigen
5. **106_Document_Map Update**: Specs 107-112 einordnen

---

*Erstellt: 2026-03-14. Nächste Aktualisierung bei signifikanter Statusänderung.*
