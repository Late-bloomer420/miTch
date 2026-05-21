# miTch Claim to Evidence Map

Stand: 2026-05-21

This file maps public-facing claims to concrete repo evidence.

## Core claims

### Claim: miTch proves only what is needed

Evidence:

- `src/packages/shared-types/src/policy.ts`
- `src/packages/shared-types/src/audit.ts`
- `src/packages/policy-engine/src/engine.ts`
- `src/packages/oid4vp/src/policy-bridge.ts`
- `src/packages/oid4vp/src/demo-flow.ts`

### Claim: raw data stays out

Evidence:

- `src/packages/shared-types/src/audit.ts`
- `src/packages/audit-log/src/index.ts`
- `src/apps/wallet-pwa/src/services/WalletService.ts`
- `docs/04-legal/MEMO_GDPR_SHREDDING.md`

### Claim: decisions are auditable

Evidence:

- `src/packages/shared-types/src/audit.ts`
- `src/packages/audit-log/src/index.ts`
- `src/packages/audit-log/L2_ANCHOR_SPEC.md`
- `src/packages/poc-hardened/src/api/eventLog.ts`
- `src/packages/poc-hardened/src/api/auditVerify.ts`

### Claim: the wallet shows requested, allowed, withheld

Evidence:

- `src/packages/data-flow/src/types.ts`
- `src/packages/data-flow/src/service.ts`
- `src/packages/data-flow/src/summary.ts`
- `src/apps/wallet-pwa/src/components/DataFlowPanel.tsx`
- `src/apps/wallet-pwa/src/__tests__/DataFlowPanel.test.tsx`

### Claim: consent manager combines decision, audit, and receipt history

Evidence:

- `src/apps/wallet-pwa/src/consent-manager/model.ts`
- `src/apps/wallet-pwa/src/components/ConsentManagerPanel.tsx`
- `src/apps/wallet-pwa/src/consent-manager/receipt-store.ts`
- `src/apps/wallet-pwa/src/App.tsx`
- `src/packages/oid4vp/src/demo-flow.ts`
- `src/packages/oid4vp/src/__tests__/e2e-flow.test.ts`
- `docs/tasks/SPRINT_02_CONSENT_MANAGER_DATA_VISUALIZATION.md`

### Claim: receipt history can be exported without raw PII

Evidence:

- `src/apps/wallet-pwa/src/consent-manager/receipt-store.ts`
- `src/apps/wallet-pwa/src/components/ConsentManagerPanel.tsx`
- `src/apps/wallet-pwa/src/consent-manager/__tests__/receipt-store.test.ts`
- `docs/03-architecture/decisions/DECISION_004_Consent_UX.md`

### Claim: identity and tracker visibility is part of the flow

Evidence:

- `src/packages/shared-types/src/audit.ts`
- `src/packages/data-flow/src/types.ts`
- `src/packages/data-flow/src/labels.ts`
- `src/apps/wallet-pwa/src/services/PrivacyAuditService.ts`
- `src/apps/wallet-pwa/src/services/WalletService.ts`
- `src/apps/wallet-pwa/src/App.tsx`

### Claim: fail-closed policy is a real system rule

Evidence:

- `src/packages/policy-engine/src/engine.ts`
- `src/packages/policy-engine/src/allow-assertion.ts`
- `src/packages/policy-engine/src/webauthn-reason-map.ts`
- `docs/03-architecture/decisions/DECISION_003_Revocation_Status.md`
- `docs/specs/70_Status_Source_Response_Hardening.md`

## Claims that need care

These claims should only be used if the supporting context is shown on the page.

- `full audit trail`
- `crypto-shredding`
- `unlinkability`
- `no raw PII custody`
- `fail-closed policy`

## Claims that should be made with proof attached

- `Identity Firewall`
- `DecisionCapsule`
- `minimum proof`
- `audit evidence`
- `user-controlled disclosure`
- `consent receipt history`
- `session-scoped receipt history`
- `metadata-only export`

## What the landing page should link to

- One live demo link
- One technical proof source
- One design / architecture reference
- One concise FAQ or terminology note
