/**
 * OID4VP Presentation Request — Parsing and validation
 */

import type {
    AuthorizationRequest,
    PresentationDefinition,
    InputDescriptor,
    ValidationResult,
} from './types';

// ─── Parser ───────────────────────────────────────────────────────

/**
 * Parse a raw authorization request object into typed AuthorizationRequest.
 * Validates required fields and structure.
 */
export function parseAuthorizationRequest(raw: unknown): ValidationResult<AuthorizationRequest> {
    if (!raw || typeof raw !== 'object') {
        return { ok: false, error: 'Request must be an object', code: 'INVALID_REQUEST' };
    }

    const r = raw as Record<string, unknown>;

    if (r['response_type'] !== 'vp_token' && r['response_type'] !== 'id_token vp_token') {
        return { ok: false, error: 'Invalid response_type', code: 'INVALID_RESPONSE_TYPE' };
    }

    if (typeof r['client_id'] !== 'string' || !r['client_id']) {
        return { ok: false, error: 'Missing client_id', code: 'MISSING_CLIENT_ID' };
    }

    if (typeof r['redirect_uri'] !== 'string' || !r['redirect_uri']) {
        return { ok: false, error: 'Missing redirect_uri', code: 'MISSING_REDIRECT_URI' };
    }

    if (typeof r['nonce'] !== 'string' || !r['nonce']) {
        return { ok: false, error: 'Missing nonce', code: 'MISSING_NONCE' };
    }

    const pdResult = parsePresentationDefinition(r['presentation_definition']);
    if (!pdResult.ok) return pdResult as ValidationResult<AuthorizationRequest>;

    return {
        ok: true,
        value: {
            response_type: r['response_type'] as AuthorizationRequest['response_type'],
            client_id: r['client_id'] as string,
            redirect_uri: r['redirect_uri'] as string,
            nonce: r['nonce'] as string,
            presentation_definition: pdResult.value!,
            state: typeof r['state'] === 'string' ? r['state'] : undefined,
            response_mode: typeof r['response_mode'] === 'string'
                ? r['response_mode'] as AuthorizationRequest['response_mode']
                : 'direct_post',
            client_metadata: r['client_metadata'] && typeof r['client_metadata'] === 'object'
                ? r['client_metadata'] as AuthorizationRequest['client_metadata']
                : undefined,
        },
    };
}

/**
 * Parse and validate a PresentationDefinition.
 */
export function parsePresentationDefinition(raw: unknown): ValidationResult<PresentationDefinition> {
    if (!raw || typeof raw !== 'object') {
        return { ok: false, error: 'presentation_definition must be an object', code: 'MISSING_PRESENTATION_DEFINITION' };
    }

    const pd = raw as Record<string, unknown>;

    if (typeof pd['id'] !== 'string' || !pd['id']) {
        return { ok: false, error: 'presentation_definition.id required', code: 'MISSING_PD_ID' };
    }

    if (!Array.isArray(pd['input_descriptors']) || pd['input_descriptors'].length === 0) {
        return { ok: false, error: 'input_descriptors must be non-empty array', code: 'MISSING_INPUT_DESCRIPTORS' };
    }

    const descriptors: InputDescriptor[] = [];
    for (const item of pd['input_descriptors']) {
        const d = item as Record<string, unknown>;
        if (typeof d['id'] !== 'string' || !d['id']) {
            return { ok: false, error: 'Each input_descriptor must have an id', code: 'INVALID_DESCRIPTOR' };
        }
        descriptors.push({
            id: d['id'] as string,
            name: typeof d['name'] === 'string' ? d['name'] : undefined,
            purpose: typeof d['purpose'] === 'string' ? d['purpose'] : undefined,
            constraints: d['constraints'] as InputDescriptor['constraints'],
        });
    }

    return {
        ok: true,
        value: {
            id: pd['id'] as string,
            name: typeof pd['name'] === 'string' ? pd['name'] : undefined,
            purpose: typeof pd['purpose'] === 'string' ? pd['purpose'] : undefined,
            input_descriptors: descriptors,
        },
    };
}

/**
 * Extract requested claim paths from a presentation definition.
 * Returns flattened list of JSONPath expressions.
 */
export function extractRequestedPaths(pd: PresentationDefinition): string[] {
    const paths: string[] = [];
    for (const descriptor of pd.input_descriptors) {
        if (descriptor.constraints?.fields) {
            for (const field of descriptor.constraints.fields) {
                paths.push(...field.path);
            }
        }
    }
    return paths;
}

/**
 * Check if a presentation definition requires selective disclosure.
 */
export function requiresSelectiveDisclosure(pd: PresentationDefinition): boolean {
    return pd.input_descriptors.some(
        d => d.constraints?.limit_disclosure === 'required'
    );
}
