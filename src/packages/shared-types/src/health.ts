/**
 * European Health Data Space (EHDS) Schema Definitions
 * Implements an extensible record model inspired by FHIR (Fast Healthcare Interoperability Resources).
 */

// Core FHIR-like resource types allow strict typing of critical fields via generics,
// while allowing 'resourceType' to drive business logic.
export interface HealthRecord<T = unknown> {
    id: string; // Internal UUID
    resourceType: string; // e.g. 'PatientSummary', 'Prescription', 'LabResult'
    status: 'final' | 'preliminary' | 'cancelled';
    effectiveDateTime: string; // ISO 8601
    performer: {
        display: string; // e.g. "Dr. Jekyll"
        reference: string; // DID e.g. "did:example:hospital-a"
    };
    content: T; // The flexible payload
}

// Specific Schemas (Reference Implementations)

/**
 * EHDS-001: Patient Summary (Emergency Data Set)
 */
export interface PatientSummary {
    bloodGroup: 'A+' | 'A-' | 'B+' | 'B-' | 'AB+' | 'AB-' | 'O+' | 'O-';
    allergies: {
        code: string; // SNOMED CT or similar
        display: string; // "Peanuts"
        criticality: 'low' | 'high' | 'unable-to-assess';
    }[];
    activeProblems: string[];
    emergencyContacts: {
        relation: string;
        phone: string;
    }[];
}

/**
 * EHDS-002: ePrescription
 */
export interface Prescription {
    medication: {
        code: string;
        display: string; // "Amoxicillin 500mg"
    };
    dosageInstruction: string; // "1 tablet every 8 hours"
    quantity: number;
    refillsRemaining: number;
}

/**
 * EHDS-003: Lab Report (Demonstrating extensibility)
 */
export interface LabResult {
    testName: string; // "Serum Cholesterol"
    valueQuantity: {
        value: number;
        unit: string;
    };
    referenceRange: {
        low: number;
        high: number;
    };
    interpretation?: 'low' | 'normal' | 'high' | 'critical';
}

// The generic VcPayload type wrapper for the Wallet
export type EhdsCredentialPayload =
    | HealthRecord<PatientSummary>
    | HealthRecord<Prescription>
    | HealthRecord<LabResult>;
