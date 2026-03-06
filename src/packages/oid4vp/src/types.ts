/**
 * OID4VP Types — OpenID for Verifiable Presentations 1.0
 * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */

// ─── Presentation Request ─────────────────────────────────────────

export interface PresentationDefinition {
    id: string;
    name?: string;
    purpose?: string;
    input_descriptors: InputDescriptor[];
}

export interface InputDescriptor {
    id: string;
    name?: string;
    purpose?: string;
    constraints?: DescriptorConstraints;
}

export interface DescriptorConstraints {
    fields?: FieldConstraint[];
    limit_disclosure?: 'required' | 'preferred';
}

export interface FieldConstraint {
    path: string[];
    filter?: Record<string, unknown>;
    optional?: boolean;
}

export interface AuthorizationRequest {
    response_type: 'vp_token' | 'id_token vp_token';
    client_id: string;
    redirect_uri: string;
    nonce: string;
    presentation_definition: PresentationDefinition;
    state?: string;
    response_mode?: 'direct_post' | 'direct_post.jwt' | 'fragment' | 'query';
    client_metadata?: ClientMetadata;
}

export interface ClientMetadata {
    client_name?: string;
    logo_uri?: string;
    tos_uri?: string;
    policy_uri?: string;
    vp_formats?: VPFormats;
}

export interface VPFormats {
    'sd-jwt'?: { alg: string[] };
    'jwt_vp'?: { alg: string[] };
    'ldp_vp'?: { proof_type: string[] };
}

// ─── VP Token ─────────────────────────────────────────────────────

export interface VerifiablePresentation {
    '@context'?: string[];
    type: string[];
    verifiableCredential?: string[];
    holder?: string;
    proof?: PresentationProof;
}

export interface PresentationProof {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws?: string;
}

export interface VPToken {
    vp_token: string | VerifiablePresentation | Array<string | VerifiablePresentation>;
    presentation_submission: PresentationSubmission;
}

export interface PresentationSubmission {
    id: string;
    definition_id: string;
    descriptor_map: DescriptorMapEntry[];
}

export interface DescriptorMapEntry {
    id: string;
    format: 'sd-jwt' | 'jwt_vp' | 'ldp_vp';
    path: string;
    path_nested?: DescriptorMapEntry;
}

// ─── Authorization Response ────────────────────────────────────────

export interface AuthorizationResponse {
    vp_token: string | VerifiablePresentation;
    presentation_submission: PresentationSubmission;
    state?: string;
}

// ─── Validation Results ────────────────────────────────────────────

export type ValidationResult<T = void> =
    | { ok: true; value?: T }
    | { ok: false; error: string; code: string };
