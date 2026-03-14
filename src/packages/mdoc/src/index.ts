/**
 * @module @mitch/mdoc
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
 * - MSO digest verification
 */

// CBOR codec
export {
    encode,
    decode,
    encodeEmbeddedCbor,
    decodeEmbeddedCbor,
    CBOR_TAGS,
} from './cbor.js';

// COSE Sign1
export {
    createSign1,
    verifySign1,
    decodeCoseSign1,
    COSE_HEADER,
    COSE_ALG,
} from './cose.js';

export type {
    CoseHeaderMap,
    CoseSign1Structure,
    Sign1CreateOptions,
    Sign1VerifyResult,
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
