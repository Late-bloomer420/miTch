/**
 * @module @mitch/mdoc/mdoc-types
 *
 * ISO 18013-5 type definitions for mdoc (Mobile Document) structures.
 * Based on publicly available ISO 18013-5:2021 references and EUDI ARF.
 *
 * These types represent the CBOR-encoded structures used in mobile
 * document presentation and verification.
 *
 * Note: COSE types (Sign1, Mac0) are defined here structurally but
 * COSE signing/verification is NOT implemented in this package yet.
 */

// ─── Namespace & Data Elements ──────────────────────────────────────────────

/**
 * ISO 18013-5 namespace identifier.
 * Standard namespace for mDL: "org.iso.18013.5.1"
 */
export type NameSpace = string;

/**
 * Data element identifier within a namespace (e.g., "family_name", "birth_date").
 */
export type DataElementIdentifier = string;

/**
 * Data element value — any CBOR-encodable value.
 */
export type DataElementValue = unknown;

/**
 * A single issuer-signed data element.
 * Each item is individually hashed and included in the MSO digest map.
 * CBOR-encoded as a map with these four keys.
 */
export interface IssuerSignedItem {
    /** Namespace this element belongs to */
    digestID: number;
    /** Random bytes for privacy (prevents brute-force of hashed values) */
    random: Uint8Array;
    /** Data element identifier (e.g., "family_name") */
    elementIdentifier: DataElementIdentifier;
    /** Data element value */
    elementValue: DataElementValue;
}

// ─── Mobile Security Object (MSO) ──────────────────────────────────────────

/**
 * Digest algorithm used in the MSO.
 * SHA-256 is mandatory per ISO 18013-5.
 */
export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Map of digestID → digest (hash of the CBOR-encoded IssuerSignedItem).
 */
export type DigestMap = Map<number, Uint8Array>;

/**
 * Per-namespace collection of digests in the MSO.
 */
export type ValueDigests = Map<NameSpace, DigestMap>;

/**
 * Device key info — the holder's public key bound to this mdoc.
 */
export interface DeviceKeyInfo {
    /** COSE_Key structure (CBOR-encoded public key) */
    deviceKey: Map<number, unknown>;
}

/**
 * Validity information for the MSO.
 */
export interface ValidityInfo {
    /** Date the MSO was signed */
    signed: Date;
    /** Start of validity period */
    validFrom: Date;
    /** End of validity period */
    validUntil: Date;
    /** Expected update date (optional) */
    expectedUpdate?: Date;
}

/**
 * Mobile Security Object — the issuer-signed metadata structure.
 * Contains digests of all IssuerSignedItems, the device key, and validity info.
 * Wrapped in a COSE_Sign1 envelope by the issuer.
 */
export interface MobileSecurityObject {
    /** MSO version (e.g., "1.0") */
    version: string;
    /** Digest algorithm used for IssuerSignedItem hashes */
    digestAlgorithm: DigestAlgorithm;
    /** Per-namespace digests of all IssuerSignedItems */
    valueDigests: ValueDigests;
    /** Holder's device key */
    deviceKeyInfo: DeviceKeyInfo;
    /** Document type (e.g., "org.iso.18013.5.1.mDL") */
    docType: string;
    /** Validity period */
    validityInfo: ValidityInfo;
}

// ─── Device Authentication ──────────────────────────────────────────────────

/**
 * Session transcript used in device authentication.
 * Binds the device signature to the specific session context.
 */
export type SessionTranscript = [
    deviceEngagementBytes: Uint8Array | null,
    eReaderKeyBytes: Uint8Array | null,
    handover: unknown,
];

/**
 * Device authentication structure.
 * The holder signs the session transcript + disclosed namespaces.
 * Can be either COSE_Mac0 or COSE_Sign1.
 */
export interface DeviceAuth {
    /** COSE_Mac0 authentication (NFC proximity) */
    deviceMac?: Uint8Array;
    /** COSE_Sign1 authentication (general) */
    deviceSignature?: Uint8Array;
}

// ─── Document Structure ─────────────────────────────────────────────────────

/**
 * Issuer-signed portion of an mdoc.
 * Contains the MSO (in COSE_Sign1 envelope) and the disclosed data elements.
 */
export interface IssuerSigned {
    /** COSE_Sign1-wrapped MobileSecurityObject (raw CBOR bytes) */
    nameSpaces: Map<NameSpace, IssuerSignedItem[]>;
    /** MSO wrapped in COSE_Sign1 (raw bytes — COSE verification is a future step) */
    issuerAuth: Uint8Array;
}

/**
 * Device-signed portion of an mdoc (selective disclosure by holder).
 */
export interface DeviceSigned {
    /** Namespaces with device-signed elements (usually empty for mdoc presentation) */
    nameSpaces: Map<NameSpace, DataElementValue>;
    /** Device authentication (COSE_Mac0 or COSE_Sign1 over session transcript) */
    deviceAuth: DeviceAuth;
}

/**
 * Complete mdoc Document — the top-level structure for presentation.
 */
export interface MdocDocument {
    /** Document type (e.g., "org.iso.18013.5.1.mDL") */
    docType: string;
    /** Issuer-signed data and MSO */
    issuerSigned: IssuerSigned;
    /** Device-signed authentication */
    deviceSigned?: DeviceSigned;
}

// ─── Constants ──────────────────────────────────────────────────────────────

/** Standard mDL document type */
export const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';

/** Standard mDL namespace */
export const MDL_NAMESPACE = 'org.iso.18013.5.1';

/** Common mDL data element identifiers */
export const MDL_ELEMENTS = {
    FAMILY_NAME: 'family_name',
    GIVEN_NAME: 'given_name',
    BIRTH_DATE: 'birth_date',
    ISSUE_DATE: 'issue_date',
    EXPIRY_DATE: 'expiry_date',
    ISSUING_COUNTRY: 'issuing_country',
    ISSUING_AUTHORITY: 'issuing_authority',
    DOCUMENT_NUMBER: 'document_number',
    PORTRAIT: 'portrait',
    AGE_OVER_18: 'age_over_18',
    AGE_OVER_21: 'age_over_21',
    DRIVING_PRIVILEGES: 'driving_privileges',
} as const;
