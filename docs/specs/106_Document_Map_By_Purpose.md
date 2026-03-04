# 106 — Document Map by Purpose (Decide / Build / Prove / Sell)

Stand: 2026-02-12
Purpose: make the repo scannable by intent, not just by number.

---

## 1) DECIDE (strategy, tradeoffs, go/no-go)
- `01_Project_OnePager.md`
- `02_Principles_and_NonNegotiables.md`
- `07_Backlog_and_Roadmap.md`
- `10_Open_Questions.md`
- `14_MVP_Risk_Register.md`
- `22_Pilot_Go_NoGo_Template.md`
- `34_Use_Case_Prioritization_Matrix.md`
- `103_GTM_Security_Decision_Framework.md`
- `105_Visual_Control_Panel.md`
- `STATE.md`

## 2) BUILD (implementation and hardening)
- `23_Implementation_Sequence_v0.md`
- `25_Sprint_1_Task_Board.md`
- `29_Implementation_Scaffold.md`
- `30_First_Code_Tasks.md`
- `31_Interface_Definitions_v0.md`
- `32_Config_Profile_v0.md`
- `41_Localhost_Test_Quickstart.md`
- `42_Pilot_Critical_Config.md`
- `57_...` to `102_...` hardening series
- `src/` and `.github/workflows/ci-security.yml`

## 3) PROVE (evidence, auditability, measurable trust)
- `38_KPI_Framework_Core_and_Business.md`
- `39_Pilot_KPI_Dashboard_Template.md`
- `40_KPI_Definitions_and_Data_Sources.md`
- `44_Evidence_Runbook.md`
- `45_Adjudication_Workflow.md`
- `46_Security_Attack_Testing.md`
- `100_Security_Profile_Score_KPI_v1.md`
- `101_WebAuthn_Native_Runtime_Usage_Metrics.md`
- `102_WebAuthn_Mismatch_and_Replay_Edge_Tests.md`

## 4) SELL (onboarding, positioning, adoption)
- `33_Business_Case_01_Age_Verification.md`
- `43_Pilot_Next_Steps_Plan.md`
- `51_RP_Onboarding_Pack.md`
- `52_RP_First_Success_Examples.md`
- `60_Legal_and_Jurisdiction_Security_Strategy.md`
- `WHAT_MITCH_IS_NOT.md`
- `104_Decision_Card_Example_ZK_Bundle_v2.md` (sample decision narrative)

---

## Fast entry points
- If you need immediate priorities: `105_Visual_Control_Panel.md`
- If you need tactical status: `STATE.md`
- If you need one-feature decision: `103_GTM_Security_Decision_Framework.md`
- If you need pilot narrative: `33`, `51`, `52`, `43`

---

## Maintenance rule
Whenever a new numbered doc is created, assign it to one of: Decide / Build / Prove / Sell.
If unclear, it is not mature enough yet.
