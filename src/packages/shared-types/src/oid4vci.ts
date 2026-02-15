/**
 * OID4VCI (OpenID for Verifiable Credential Issuance) Type Definitions
 * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 * 
 * API contracts for issuer-wallet communication
 */

import { VerifiableCredential, DID } from './vc';

/**
 * Credential Issuer Metadata
 * Returned from /.well-known/openid-credential-issuer
 */
export interface CredentialIssuerMetadata {
    /**
     * Issuer's identifier (URL)
     */
    credential_issuer: string;

    /**
     * Credential endpoint URL
     */
    credential_endpoint: string;

    /**
     * Optional authorization server
     */
    authorization_server?: string;

    /**
     * Supported credentials
     */
    credentials_supported: CredentialSupported[];

    /**
     * Optional batch credential endpoint
     */
    batch_credential_endpoint?: string;
}

/**
 * Supported credential configuration
 */
export interface CredentialSupported {
    /**
     * Identifier for this credential type
     */
    id: string;

    /**
     * Format (e.g., 'jwt_vc_json', 'ldp_vc')
     */
    format: 'jwt_vc_json' | 'ldp_vc' | 'jwt_vc' | 'ldp';

    /**
     * Credential types
     */
    types: string[];

    /**
     * Optional cryptographic binding methods
     */
    cryptographic_binding_methods_supported?: string[];

    /**
     * Optional proof types
     */
    credential_signing_alg_values_supported?: string[];
}

/**
 * Credential request (from wallet to issuer)
 */
export interface CredentialRequest {
    /**
     * Format requested
     */
    format: 'jwt_vc_json' | 'ldp_vc';

    /**
     * Credential type(s) requested
     */
    types?: string[];

    /**
     * Credential definition (alternative to types)
     */
    credential_definition?: {
        '@context': string[];
        type: string[];
    };

    /**
     * Optional proof of possession
     */
    proof?: {
        proof_type: string;
        jwt: string;
    };
}

/**
 * Credential response (from issuer to wallet)
 */
export interface CredentialResponse {
    /**
     * Format of returned credential
     */
    format: string;

    /**
     * The credential (structure depends on format)
     */
    credential: VerifiableCredential | string; // String for JWT format

    /**
     * Optional: nonce for next request
     */
    c_nonce?: string;

    /**
     * Optional: validity of c_nonce
     */
    c_nonce_expires_in?: number;
}

/**
 * Credential offer (issuer to wallet, to initiate flow)
 */
export interface CredentialOffer {
    /**
     * Issuer URL
     */
    credential_issuer: string;

    /**
     * Credentials being offered
     */
    credentials: string[]; // Array of credential IDs from metadata

    /**
     * Optional pre-authorized code grant
     */
    grants?: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: {
            'pre-authorized_code': string;
            user_pin_required?: boolean;
        };
    };
}

/**
 * Error response (OID4VCI standard errors)
 */
export interface OID4VCIError {
    error:
    | 'invalid_request'
    | 'invalid_token'
    | 'unsupported_credential_type'
    | 'unsupported_credential_format'
    | 'invalid_proof'
    | 'invalid_encryption_parameters';

    error_description?: string;

    error_uri?: string;
}
