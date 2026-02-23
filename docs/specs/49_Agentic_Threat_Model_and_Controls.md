# 49 — Agentic Threat Model & Controls

Stand: 2026-02-11

## Scope
Risks from AI coding agents, tool-using agents, and automation workflows affecting miTch security/privacy guarantees.

---

## Threat Classes

## T-A1: Policy Drift by AI Refactor
- **Description:** Agent modifies policy/deny logic for convenience/performance.
- **Impact:** Fail-open behavior, over-disclosure.
- **Controls:**
  - CODEOWNERS on security-critical paths
  - Mandatory human review for policy/security diffs
  - Deny-code regression tests as merge gate

## T-A2: Tool Overreach
- **Description:** Agent executes tools beyond intended scope.
- **Impact:** secret exposure, unauthorized changes, unsafe operations.
- **Controls:**
  - Per-task tool allowlists
  - Least-privilege runtime profile
  - Explicit approvals for destructive/external actions

## T-A3: Indirect Prompt Injection
- **Description:** Untrusted external text instructs agent to bypass safeguards.
- **Impact:** malicious edits, exfiltration, policy weakening.
- **Controls:**
  - Untrusted-input labeling
  - Never execute instructions from fetched content by default
  - Security checks independent of prompt compliance

## T-A4: Supply Chain Poisoning via AI Suggestions
- **Description:** Agent adds vulnerable/malicious dependencies.
- **Impact:** compromise risk in build/runtime.
- **Controls:**
  - dependency pinning
  - SBOM + vuln scanning
  - allowlist package sources

## T-A5: Secret Leakage in Logs/Artifacts
- **Description:** agent writes sensitive data into logs, docs, commits.
- **Impact:** credential/data breach.
- **Controls:**
  - secret scanning pre-commit/CI
  - redaction enforcement
  - no secrets in env examples/docs

## T-A6: Autonomous Goal Hijacking
- **Description:** agent optimizes for throughput over safety constraints.
- **Impact:** weakened controls, hidden risk acceptance.
- **Controls:**
  - immutable non-negotiables in tests/config
  - policy checks as hard CI blockers
  - human sign-off for risk exceptions

---

## Pilot Minimum Control Set
1. Mandatory review on `src/api`, `src/binding`, `src/policy`, `src/proof`, `src/receipt`.
2. CI must pass: compile, tests, swarm test, evidence run.
3. Secret scanning + dependency scan required before release.
4. Untrusted-input handling explicitly documented in contributor policy.
