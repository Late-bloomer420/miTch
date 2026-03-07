/**
 * OID4VP VP Token — Generation and parsing
 */

function randomHex(bytes: number): string {
    const arr = new Uint8Array(bytes);
    globalThis.crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
import type {
    VerifiablePresentation,
    PresentationSubmission,
    DescriptorMapEntry,
    VPToken,
    PresentationDefinition,
} from './types';

// ─── VP Token Builder ─────────────────────────────────────────────

export interface VPTokenBuildOptions {
    holder: string;
    credentials: string[];           // SD-JWT or JWT-VC strings
    definition: PresentationDefinition;
    format?: 'sd-jwt' | 'jwt_vp' | 'ldp_vp';
}

/**
 * Build a VP Token for a given presentation definition.
 * For SD-JWT credentials, each credential is mapped to its descriptor.
 */
export function buildVPToken(opts: VPTokenBuildOptions): VPToken {
    const { holder: _holder, credentials, definition, format = 'sd-jwt' } = opts;

    const submissionId = `sub-${randomHex(8)}`;

    const descriptorMap: DescriptorMapEntry[] = definition.input_descriptors.map((desc, i) => ({
        id: desc.id,
        format,
        path: credentials.length === 1 ? '$' : `$[${i}]`,
    }));

    const submission: PresentationSubmission = {
        id: submissionId,
        definition_id: definition.id,
        descriptor_map: descriptorMap,
    };

    // For SD-JWT format, vp_token is the credential string directly
    // For multi-credential, wrap in array
    const vpToken = credentials.length === 1 ? credentials[0] : credentials;

    return { vp_token: vpToken as string, presentation_submission: submission };
}

/**
 * Build a W3C Verifiable Presentation envelope.
 */
export function buildVerifiablePresentation(opts: {
    holder: string;
    credentials: string[];
    context?: string[];
}): VerifiablePresentation {
    return {
        '@context': opts.context ?? ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        holder: opts.holder,
        verifiableCredential: opts.credentials,
    };
}

/**
 * Parse a vp_token string back into its components.
 * Handles both single credential and array.
 */
export function parseVPToken(raw: unknown): {
    credentials: string[];
    isArray: boolean;
} {
    if (typeof raw === 'string') {
        return { credentials: [raw], isArray: false };
    }
    if (Array.isArray(raw)) {
        return {
            credentials: raw.filter(c => typeof c === 'string') as string[],
            isArray: true,
        };
    }
    // W3C VP object
    if (raw && typeof raw === 'object') {
        const vp = raw as VerifiablePresentation;
        return {
            credentials: vp.verifiableCredential ?? [],
            isArray: false,
        };
    }
    return { credentials: [], isArray: false };
}

/**
 * Validate that a presentation_submission matches a presentation_definition.
 */
export function validateSubmission(
    submission: PresentationSubmission,
    definition: PresentationDefinition
): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (submission.definition_id !== definition.id) {
        errors.push(`definition_id mismatch: expected ${definition.id}, got ${submission.definition_id}`);
    }

    const requiredIds = new Set(definition.input_descriptors.map(d => d.id));
    const submittedIds = new Set(submission.descriptor_map.map(d => d.id));

    for (const id of requiredIds) {
        if (!submittedIds.has(id)) {
            errors.push(`Missing descriptor for input_descriptor id: ${id}`);
        }
    }

    return { valid: errors.length === 0, errors };
}
