# T-30: European Health Data Space (EHDS) Blueprint

## 1. Objective
Implement a reference architecture for the secure, patient-controlled sharing of health data (e.g., Patient Summary, ePrescription) using the miTch Wallet stack. This blueprint explicitly targets the cross-border interoperability requirements of the EHDS regulation.

## 2. Key Requirements (EHDS)

### 2.1 Patient Summary VC (PS-VC)
A Verifiable Credential containing minimal emergency data:
-   **Structure**: Based on HL7 FHIR IPS (International Patient Summary).
-   **Fields**: Allergies, Current Medications, Blood Type, Implanted Devices.
-   **Privacy**: Fields must be selectively disclosable (SD-JWT).

### 2.2 ePrescription VC (eRx-VC)
-   **Lifecycle**: Issued by Doctor -> Presented at Pharmacy -> Burned (Marked as Dispensed).
-   **Double-Spend Protection**: Must use a centralized revocation list or nullifier (on-chain) to prevent re-dispensing elsewhere.

## 3. Technical Implementation

### 3.1 Data Model
```typescript
interface PatientSummaryVC {
    type: ["VerifiableCredential", "PatientSummaryCredential"],
    credentialSubject: {
        id: "did:mitch:patient-123",
        allergies: ["Penicillin", "Peanuts"],
        medications: ["Metformin 500mg"],
        implantableDevices: [],
        bloodType: "A+"
    }
}
```

### 3.2 "Emergency Break-Glass" Policy
-   **Standard Access**: Requires user biometric consent.
-   **Emergency Access**: If `verifier_type == "EMERGENCY_ER"`, allow access *without* immediate consent but trigger a high-priority Audit Alert ("Break-Glass Event") + notify user.

### 3.3 Cross-Border Translation Layer
-   The Wallet UI must be able to render the medical terms in the local language of the Verifier (e.g., displaying "Penicillin Allergy" in Spanish if Verifier is `did:es:hospital`).

## 4. Work Packages

1.  **Schema Definition**: Define the TS interfaces for `PatientSummaryCredential` and `ePrescriptionCredential`.
2.  **Wallet Seeding**: Add a mock `PATIENT_SUMMARY_CREDENTIAL` to the Wallet initialization.
3.  **Policy Rule**: Add an `emergency-access` rule to `DEFAULT_POLICY`.
4.  **UI Update**: Add a "Health" tab to the Wallet PWA to view these specific credentials.

## 5. Success Criteria (Demo)
A user can log into a "Spanish Hospital Portal" (Mock) and share their "Allergies" without sharing their "HIV Status" or full history.
