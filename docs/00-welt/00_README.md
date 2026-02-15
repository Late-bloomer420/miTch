# miTch - Context Pack (for AI + humans)

> Note: `README.md` is the short human-facing overview.
> This file (`00_README.md`) is the detailed project/context index.

**Purpose:** This folder is a compact, high-signal context bundle for the *miTch* project (user-sovereign identity + authorization).
It is designed to be pasted into other AI systems (Gemini, Claude, AI Studio) or shared with collaborators without losing the core invariants.

**Build date:** 2026-02-11 (Europe/Vienna)

## How to use
- Quick overview: `README.md`
- Start with: `01_Project_OnePager.md`
- If the other system tends to hallucinate or "optimize UX by breaking privacy", also paste:
  - `02_Principles_and_NonNegotiables.md`
  - `04_Data_Flows_and_PII_Boundaries.md`
  - `05_Threat_Model.md`
  - `08_Prompts_for_Collaboration.md` (ready-made system prompts)

## Integrity notes
- These documents prioritize **privacy, minimization, user sovereignty, and fail-closed logic** over convenience.
- Anything implying centralized identity storage, profiling/analytics, blockchain dependency, asset custody, or "trust us" security is considered **out of scope** and must be rejected.

## Contents
- `01_Project_OnePager.md` - shareable overview
- `02_Principles_and_NonNegotiables.md` - invariants + constraints
- `03_Architecture_Core.md` - components + responsibilities
- `04_Data_Flows_and_PII_Boundaries.md` - how to keep PII inside state DBs
- `05_Threat_Model.md` - failure analysis, metadata leaks, mitigations
- `06_Policy_Engine_Spec.md` - policy artifacts + enforcement rules
- `07_Backlog_and_Roadmap.md` - active concept-phase backlog/roadmap
- `archive/07_Backlog_and_Implemented_Tasks_legacy_snapshot.md` - legacy snapshot ("implemented" framing)
- `08_Prompts_for_Collaboration.md` - system prompts for other AIs
- `09_Glossary.md`
- `10_Open_Questions.md`
- `11_MVP_Gap_Analysis.md` - technical gaps from concept to MVP
- `12_MVP_Execution_Plan_6_Weeks.md` - practical implementation plan
- `13_MVP_Readiness_Checklist.md` - go/no-go criteria for pilot
- `14_MVP_Risk_Register.md` - active risk tracking for MVP delivery
- `15_MVP_Work_Breakdown.md` - epics/tasks/owners/estimates for delivery
- `16_MVP_Architecture_Decision_Log.md` - ADR index for hard technical choices
- `17_API_Contract_v0.md` - requester/verifier contract draft for MVP
- `18_Test_Plan_Adversarial_and_E2E.md` - adversarial + E2E test strategy
- `19_Data_Retention_Matrix.md` - field-level retention and purge policy
- `20_Canonicalization_and_Binding_Spec_v0.md` - deterministic binding + anti-replay spec
- `21_Deny_Reason_Code_Catalog.md` - normative deny code source of truth
- `22_Pilot_Go_NoGo_Template.md` - formal pilot decision template
- `23_Implementation_Sequence_v0.md` - concrete build order to MVP
- `24_Repo_Setup_and_GitHub_Linking.md` - current git/remote status + linking steps
- `25_Sprint_1_Task_Board.md` - week-1 execution board with acceptance criteria
- `26_Repository_Hygiene_Plan.md` - cleanup plan for dependency/build artifacts
- `27_ADR_Closure_Record.md` - accepted MVP architecture decisions (binding)
- `28_Test_Vector_Pack_v0.md` - canonicalization/binding normative vectors
- `29_Implementation_Scaffold.md` - target module/file structure for coding phase
- `30_First_Code_Tasks.md` - immediate implementation backlog (top 10)
- `31_Interface_Definitions_v0.md` - internal contracts for parallel implementation
- `32_Config_Profile_v0.md` - safe runtime defaults and config shape
- `33_Business_Case_01_Age_Verification.md` - first business case definition (ICP/value/KPI)
- `34_Use_Case_Prioritization_Matrix.md` - weighted use-case selection matrix
- `35_Product_Architecture_Layers.md` - scope-safe layering (Core/Shield/Orchestrator)
- `36_Phase2_Shield_and_AI_Orchestration_Roadmap.md` - future expansion roadmap after Core MVP
- `37_Privacy_Policy_Language_for_Web_and_AI.md` - shared policy grammar concept for web+AI controls
- `38_KPI_Framework_Core_and_Business.md` - security + business KPI baseline and targets
- `39_Pilot_KPI_Dashboard_Template.md` - weekly KPI reporting template for pilot operations
- `40_KPI_Definitions_and_Data_Sources.md` - formulas, telemetry sources, and KPI ownership
- `41_Localhost_Test_Quickstart.md` - run/test instructions for local verifier service
- `42_Pilot_Critical_Config.md` - required env config for protected pilot operation
- `43_Pilot_Next_Steps_Plan.md` - immediate pilot hardening/evidence/execution plan
- `src/proof/keySource.ts` + adapters (`file/http`) - pluggable key source strategy for pilot realism
- `44_Evidence_Runbook.md` - reproducible scenario runbook for pilot evidence (B1)
- `45_Adjudication_Workflow.md` - practical process to measure false-deny with real case classification
- `46_Security_Attack_Testing.md` - pilot-scope adversarial testing incl. swarm simulation
- `47_Risk_Register_Extended_Human_and_Governance.md` - socio-technical and governance risk register
- `48_Mitigations_ProofFatigue_PolicyTamper_Recovery_GDPR.md` - concrete mitigation plan for key non-technical risks
- `49_Agentic_Threat_Model_and_Controls.md` - threat model for AI-agent misuse and automated abuse
- `50_AI_Agent_Governance_Policy.md` - policy baseline for safe AI-assisted development
- `51_RP_Onboarding_Pack.md` - RP #1 onboarding essentials and failure mapping
- `52_RP_First_Success_Examples.md` - copy/paste first-success and failure examples
- `53_TEE_Readiness_Gap.md` - explicit gap analysis for true TEE-backed policy execution
- `54_External_Security_Findings_Integration.md` - mapped action plan from external security review
- `55_External_Findings_Expanded_Systemic_Risks.md` - integrated systemic/scale/governance findings from expanded review
- `56_Risk_to_Roadmap_Mapping.md` - concrete owner/phase mapping for newly tracked risks
- `57_Proof_Fatigue_Control_v1.md` - implemented baseline control for repeated high-risk prompt abuse
- `58_Revocation_Baseline_v1.md` - credential/key revocation baseline and next-step plan
- `59_Supply_Chain_Hardening_v1.md` - baseline + near-term controls against dependency compromise
- `60_Legal_and_Jurisdiction_Security_Strategy.md` - backdoor pressure and jurisdiction conflict strategy
- `.github/workflows/ci-security.yml` - merge-gate CI for tests, evidence, KPI threshold check, swarm test, and dependency audit
- `61_Jurisdiction_Compatibility_Gate_v1.md` - strict jurisdiction mismatch deny baseline
- `62_Revocation_Status_Resolver_v2_Scaffold.md` - env/http credential status resolver scaffold and fail-closed mapping
- `63_Deny_Code_Credential_Revoked.md` - dedicated deny code for credential-level revocation outcomes
- `64_Deny_Code_Status_Source_Unavailable.md` - dedicated deny code for revocation/status source outages
- `65_KPI_Deny_Category_Visibility.md` - explicit KPI fields for critical deny categories
- `66_Dashboard_Security_KPI_Box.md` - dashboard section for high-signal deny-category KPIs
- `67_Strong_ReAuth_Scaffold_v1.md` - strict re-auth/WebAuthn hook for proof-fatigue bypass hardening
- `68_StatusList2021_Input_Shape_Scaffold.md` - request/schema readiness for StatusList2021 credential status metadata
- `69_StatusList2021_Index_Check_Light.md` - light index-based revocation checks (env/http)
- `70_Status_Source_Response_Hardening.md` - fail-closed validation for status-provider response shape
- `71_Revoked_Only_Cache_Safety_Model.md` - conservative local cache model (revoked-only, bounded, short TTL)
- `72_KPI_Revoked_Cache_Observability.md` - KPI counters for revoked-cache hits/stores
- `73_Dashboard_Revoked_Cache_KPI.md` - dashboard visibility for revoked-cache counters
- `74_Security_KPI_Alert_Thresholds_v1.md` - pilot alert thresholds for status outage and revoked-cache dependency
- `75_KPI_Check_SoftFail_Mode.md` - warning/critical exit behavior control for KPI checks
- `.env.strict.example` - strict production-like env profile for hardening and KPI enforcement
- `76_Strict_Profile_Example.md` - quick guide for strict profile usage
- `77_StatusList_Reference_Validation_v3_Light.md` - secure URL/index validation for status-list references
- `78_WebAuthn_Strong_ReAuth_Window_v2.md` - stronger re-auth checks with challenge and freshness window
- `79_WebAuthn_Challenge_Replay_Protection.md` - one-time challenge reuse protection for strong re-auth
- `80_WebAuthn_RPID_Origin_Binding_v3.md` - RP-ID and origin binding checks for strict re-auth
- `81_KPI_WebAuthn_Drift_Visibility.md` - KPI + dashboard visibility for invalid re-auth evidence
- `82_DID_Resolver_Hardening_v1_Scaffold.md` - small-batch plan for resolver quorum and consistency hardening
- `83_DID_Resolver_Config_Profile_v1.md` - env profile draft for resolver quorum/timeout hardening
- `84_DID_Resolver_Quorum_Logic_v1.md` - implemented multi-source key resolver quorum behavior
- `85_Resolver_Inconsistency_Observability_v1.md` - resolver telemetry surfaced via KPI/dashboard
- `86_KPI_Resolver_Inconsistency_Alerts.md` - KPI threshold alerts for resolver inconsistency drift
- `87_KPI_Resolver_Quorum_Failure_Alerts.md` - KPI threshold alerts for resolver quorum-failure drift
- `88_Deny_Code_Resolver_Quorum_Failed.md` - dedicated deny mapping for resolver no-quorum outcomes
- `89_KPI_Deny_Resolver_Quorum_Failed_Alerts.md` - KPI thresholds for resolver no-quorum deny pressure
- `90_No_Silent_Allow_Assertion.md` - explicit test assertion for deny-biased no-quorum behavior
- `91_Trust_Guardrail_False_Allow_Zero_Tolerance.md` - zero-tolerance guardrail for confirmed false-allow outcomes
- `92_Cost_KPI_Estimation_v1.md` - estimated cost KPI fields in `/kpi` and dashboard
- `93_PQ_Readiness_Crypto_Agility_v1.md` - configurable algorithm allowlist baseline for future PQ migration
- `94_WebAuthn_Crypto_Verification_Scaffold_v3.md` - signed assertion verification scaffold for strong re-auth
- `95_WebAuthn_Native_Verifier_Hook_v1.md` - verifier interface hook for future native authenticator checks
- `96_WebAuthn_Native_Hook_Bound_Adapter_Evidence.md` - native hook now requires request-bound cryptographic adapter evidence
- `97_WebAuthn_Config_Health_Guardrail.md` - KPI/check guardrail for strong re-auth config health
- `98_WebAuthn_Native_Mode_Usage_Visibility.md` - KPI/dashboard/check visibility for native mode posture
- `99_WebAuthn_Allowlist_Mode_Drift_Warning.md` - warning signal when strong re-auth still runs allowlist verification mode
- `100_Security_Profile_Score_KPI_v1.md` - compact 0-100 security posture score in KPI/dashboard/checks
- `101_WebAuthn_Native_Runtime_Usage_Metrics.md` - native WebAuthn runtime attempt/success/deny KPI visibility
- `102_WebAuthn_Mismatch_and_Replay_Edge_Tests.md` - adversarial tests for signed/native context mismatch and challenge replay denial
- `STATE.md` - single-screen current state (Now/Next/Later, blockers, safe runtime reminders)
- `src/tools/kpiCheckCli.ts` - CLI check for KPI thresholds (`npm run kpi:check`)
- `src/api/metrics.ts` - in-service counters for basic KPI telemetry (`GET /metrics`)
- `src/api/eventLog.ts` + `src/api/kpi.ts` - structured audit events and derived KPI snapshot (`GET /kpi`)
- `src/api/auditVerify.ts` - audit hash-chain integrity verification (`GET /audit/verify`)
- `LICENSE` - MIT open-source license
- `NOTICE` - ownership and positioning notice
- `CODEOWNERS` - default review ownership
- `CONTRIBUTING.md` - contribution workflow and required checks
- `WHAT_MITCH_IS_NOT.md` - guardrails / positioning
