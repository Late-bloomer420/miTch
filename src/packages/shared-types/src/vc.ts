/**
 * W3C Verifiable Credentials Data Model
 * https://www.w3.org/TR/vc-data-model/
 * 
 * This module defines TypeScript types for Verifiable Credentials (VC)
 * and Verifiable Presentations (VP) aligned with W3C standards.
 */

/**
 * DID (Decentralized Identifier)
 * Format: did:method:identifier
 */
export type DID = string;

/**
 * URI (Uniform Resource Identifier)
 */
export type URI = string;

/**
 * ISO 8601 DateTime string
 */
export type DateTime = string;

/**
 * JSON-LD Context
 * Defines the semantic meaning of terms in the credential
 */
export type Context = string | Record<string, unknown> | Array<string | Record<string, unknown>>;

/**
 * Proof mechanism for cryptographic verification
 * Uses JWT format for PoC simplicity
 */
export interface Proof {
    /**
     * Type of proof (e.g., 'JwtProof2020', 'Ed25519Signature2020')
     */
    type: string;

    /**
     * ISO 8601 timestamp of proof creation
     */
    created: DateTime;

    /**
     * Purpose of the proof (e.g., 'assertionMethod', 'authentication')
     */
    proofPurpose: string;

    /**
     * DID URL of the verification method used
     */
    verificationMethod: URI;

    /**
     * JWT compact serialization (for JwtProof2020)
     */
    jwt?: string;

    /**
     * JWS signature (for other proof types)
     */
    jws?: string;
}

/**
 * Generic Verifiable Credential
 * T: Type of credentialSubject (defaults to flexible Record)
 */
export interface VerifiableCredential<T = Record<string, unknown>> {
    /**
     * JSON-LD context defining the semantic meaning
     */
    '@context': Context[];

    /**
     * Unique identifier for this credential
     */
    id: URI;

    /**
     * Type identifiers for this credential
     * Must include 'VerifiableCredential'
     */
    type: string[];

    /**
     * DID of the entity that issued the credential
     */
    issuer: DID | { id: DID; name?: string };

    /**
     * ISO 8601 timestamp of issuance
     */
    issuanceDate: DateTime;

    /**
     * Optional expiration date
     */
    expirationDate?: DateTime;

    /**
     * The claims about the subject
     */
    credentialSubject: T & { id: DID };

    /**
     * Cryptographic proof of authenticity
     */
    proof?: Proof;

    /**
     * Additional credential metadata
     */
    credentialStatus?: {
        id: URI;
        type: string;
    };
}

/**
 * Age Credential Subject (specific type for PoC)
 */
export interface AgeCredentialSubject {
    /**
     * DID of the credential subject
     */
    id: DID;

    /**
     * Date of birth in ISO 8601 format (YYYY-MM-DD)
     */
    dateOfBirth: string;

    /**
     * Optional computed claim for age verification
     */
    isOver18?: boolean;
}

/**
 * Typed Age Credential
 */
export type AgeCredential = VerifiableCredential<AgeCredentialSubject>;

/**
 * Verifiable Presentation
 * Container for presenting one or more VCs
 */
export interface VerifiablePresentation {
    /**
     * JSON-LD context
     */
    '@context': Context[];

    /**
     * Optional identifier for this presentation
     */
    id?: URI;

    /**
     * Type identifiers
     * Must include 'VerifiablePresentation'
     */
    type: string[];

    /**
     * One or more verifiable credentials
     */
    verifiableCredential: VerifiableCredential[];

    /**
     * DID of the holder presenting the credentials
     */
    holder: DID;

    /**
     * Replay Protection Deadline
     * Timestamp (ms or ISO) after which this VP should be rejected.
     */
    validUntil?: string | number;

    /**
     * Cryptographic proof that the holder created this presentation
     */
    proof?: Proof;
}

/**
 * Presentation Definition Request
 * Describes what the verifier is requesting
 */
export interface PresentationDefinition {
    /**
     * Unique identifier for this request
     */
    id: string;

    /**
     * Input descriptors defining what credentials are needed
     */
    input_descriptors: Array<{
        id: string;
        name?: string;
        purpose?: string;
        constraints: {
            fields: Array<{
                path: string[];
                filter?: Record<string, unknown>;
            }>;
        };
    }>;
}

/**
 * Basic DID Document structure
 * Simplified for PoC (full spec is more complex)
 */
export interface DIDDocument {
    '@context': Context[];
    id: DID;
    verificationMethod?: Array<{
        id: URI;
        type: string;
        controller: DID;
        publicKeyJwk?: Record<string, unknown>;
    }>;
    authentication?: URI[];
    assertionMethod?: URI[];
}
