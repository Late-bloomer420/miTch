# Implementation Plan: Verifiable AI Pipeline Demo

## 1. Goal
Build a working end-to-end simulation of the "Pharma Insight" case using existing miTch mocks.

## 2. Work Packages (WPs)

### WP 1: Data Generation (`issuer-mock`)
- **Task 1.1:** Create a new endpoint `GET /v1/demo/training-batch`.
- **Task 1.2:** Generate 10 mock SD-JWT VCs containing: `patient_name`, `age`, `zip_code`, `systolic_bp`, `diastolic_bp`, `medication`.
- **Task 1.3:** Sign with the mock issuer key.

### WP 2: The Guardian Logic (`verifier-demo` backend)
- **Task 2.1:** Create a `GuardianService.ts`.
- **Task 2.2:** Integrate `trustListResolver` to simulate Hospital-to-Pharma trust.
- **Task 2.3:** Wire the `PolicyEngine` with a "Minimization Policy" that hashes names and buckets ages.
- **Task 2.4:** Wrap the processing loop in `EphemeralKey.use()`.

### WP 3: The Cockpit UI (`wallet-pwa` extension)
- **Task 3.1:** Create `src/views/AIGuardianDemo.tsx`.
- **Task 3.2:** Implement a 3-column layout (Source -> Guardian -> Proof).
- **Task 3.3:** Add "Live" countdown timer for the Ephemeral window.
- **Task 3.4:** Display the final `ShredProof` JSON after completion.

## 3. Success Criteria
- [ ] User can see raw data enter the Guardian.
- [ ] User sees data being transformed (ZKQF).
- [ ] User sees the "SHREDDED" status and the verifiable receipt.
- [ ] No raw data remains in the `verifier-demo` memory state.
