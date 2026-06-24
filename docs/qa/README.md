# QA Evidence Records — Index

> **Rolle:** Dated, point-in-time **evidence records** (Beweis-Snapshots). Each file captures
> verification done *on its date* — they are **not** authoritative task-tracking and are not kept
> current. For "what is done / open" see [`../BACKLOG.md`](../BACKLOG.md); for the operational
> health snapshot see [`../../STATE.md`](../../STATE.md).
>
> **Reading rule:** treat every record as true *as of its date* only. A later record or `master`
> supersedes an earlier one where they differ. Do not cite these as current state.

## Records

| File | Date | What it evidences |
|---|---|---|
| [`WALLET_RECOVERY_RC_2026-06-04.md`](WALLET_RECOVERY_RC_2026-06-04.md) | 2026-06-04 | Wallet recovery RC QA run (full-suite evidence baseline). |
| [`PILOT_FLOW_RERUN_2026-06-04.md`](PILOT_FLOW_RERUN_2026-06-04.md) | 2026-06-04 | Pilot demo flow re-run record. |
| [`MIT-10-demo-evidence.md`](MIT-10-demo-evidence.md) (+ `MIT-10-wallet.png`) | 2026-06-04 | MIT-10 local demo flow re-run, with wallet screenshot. |
| [`BIG_AUDIT_CONSTANTS_CONTRACTS_2026-06-04.md`](BIG_AUDIT_CONSTANTS_CONTRACTS_2026-06-04.md) | 2026-06-04 | Big-audit slice: constants & contracts review. |
| [`BIG_AUDIT_SCENARIO_FIXTURES_2026-06-04.md`](BIG_AUDIT_SCENARIO_FIXTURES_2026-06-04.md) | 2026-06-04 | Big-audit slice: demo-scenario fixtures (S2-04). |
| [`BIG_AUDIT_STATUSLIST_FIXTURES_2026-06-04.md`](BIG_AUDIT_STATUSLIST_FIXTURES_2026-06-04.md) | 2026-06-04 | Big-audit slice: StatusList test fixtures (S2-05). |
| [`CAPSULE_SIG_ROOTCAUSE_2026-06-18.md`](CAPSULE_SIG_ROOTCAUSE_2026-06-18.md) | 2026-06-18 | Root-cause + resolution of the "capsule signature verification failures" (AskMI↔miTch rebrand AAD drift, not a crypto defect). |

_Sighting (H-10): index added 2026-06-24; all entries confirmed as dated evidence records, none acting as task-tracking._
