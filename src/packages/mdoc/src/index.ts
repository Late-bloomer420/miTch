/**
 * @module @askmi/mdoc
 *
 * Minimal ISO 18013-5 mdoc foundation package.
 * Provides CBOR codec, COSE Sign1, and mdoc type definitions.
 *
 * Current scope:
 * - CBOR encode/decode (via cborg)
 * - COSE_Sign1 create/verify (ES256)
 * - ISO 18013-5 type definitions
 *
 * Future (not yet implemented):
 * - COSE Mac0
 * - mdoc document parsing and construction
 */

// CBOR codec
export {
    encode,
    decode,
    decodeMdoc,
    encodeEmbeddedCbor,
    decodeEmbeddedCbor,
    CBOR_TAGS,
} from './cbor.js';

// COSE Sign1
export {
    createSign1,
    verifySign1,
    decodeCoseSign1,
    createMac0,
    verifyMac0,
    decodeCoseMac0,
    deriveSessionMacKey,
    COSE_HEADER,
    COSE_ALG,
    COSE_MAC_ALG,
} from './cose.js';

export type {
    CoseHeaderMap,
    CoseSign1Structure,
    CoseMac0Structure,
    Sign1CreateOptions,
    Sign1VerifyResult,
    Mac0CreateOptions,
    Mac0VerifyResult,
} from './cose.js';

// mdoc types
export type {
    NameSpace,
    DataElementIdentifier,
    DataElementValue,
    IssuerSignedItem,
    DigestAlgorithm,
    DigestMap,
    ValueDigests,
    DeviceKeyInfo,
    ValidityInfo,
    MobileSecurityObject,
    SessionTranscript,
    DeviceAuth,
    IssuerSigned,
    DeviceSigned,
    MdocDocument,
} from './mdoc-types.js';

export {
    MDL_DOCTYPE,
    MDL_NAMESPACE,
    MDL_ELEMENTS,
} from './mdoc-types.js';

// MSO digest verification
export {
    digestItem,
    verifyMsoDigests,
    extractAndVerifyMso,
} from './mso.js';

export type {
    InvalidDigestItem,
    MsoDigestResult,
    MsoVerifyResult,
} from './mso.js';

// COSE_Key import/export
export {
    importCoseKey,
    exportCoseKey,
    COSE_KEY,
} from './cose-key.js';

// Device authentication
export {
    verifyDeviceSignature,
    verifyDeviceMac,
    verifyDeviceAuth,
} from './device-auth.js';

export type {
    DeviceAuthResult,
} from './device-auth.js';

// MSO validity + docType verification
export {
    verifyMsoValidity,
    verifyDocType,
} from './validity.js';

export type {
    ValidityResult,
} from './validity.js';

// x5chain certificate extraction
export {
    extractX5Chain,
    importPublicKeyFromCert,
    extractSpkiFromCert,
    COSE_HEADER_X5CHAIN,
} from './x5chain.js';

export type {
    X5ChainResult,
    TrustAnchorVerifier,
} from './x5chain.js';

// mdoc document parser
export {
    parseDeviceResponse,
} from './mdoc-parser.js';

export type {
    DeviceResponse,
} from './mdoc-parser.js';

// Full offline verification
export {
    verifyMdocOffline,
} from './verifier.js';

export type {
    MdocVerificationResult,
    MdocVerifyOptions,
    VerificationStep,
} from './verifier.js';

// mdoc document builder (issuance)
export {
    buildIssuerSignedItems,
    buildMobileSecurityObject,
    signMobileSecurityObject,
    buildMdocDocument,
    buildDeviceResponse,
} from './mdoc-builder.js';

export type {
    NamespaceClaims,
    MdocBuildOptions,
    MdocBuildResult,
} from './mdoc-builder.js';

// Device Engagement (Proximity)
export {
    buildDeviceEngagement,
    createEngagementUri,
} from './engagement.js';
