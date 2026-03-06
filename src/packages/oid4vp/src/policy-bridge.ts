/**
 * OID4VP ↔ Policy Engine Bridge
 *
 * Connects an OID4VP Authorization Request to the miTch policy-engine
 * consent flow. This is the integration point where:
 * 1. An incoming OID4VP request is parsed + validated
 * 2. The request is converted to a VerifierRequest for policy evaluation
 * 3. The policy engine evaluates and returns ALLOW/DENY/PROMPT
 * 4. On ALLOW: the authorization response is built with VP Token
 * 5. On DENY: the flow is terminated with an error
 * 6. On PROMPT: user consent is requested before proceeding
 */

import type { AuthorizationRequest, AuthorizationResponse, PresentationDefinition, ValidationResult } from './types';
import { parseAuthorizationRequest } from './presentation-request';
import { buildAuthorizationResponse } from './response-builder';
import { extractRequestedPaths, requiresSelectiveDisclosure } from './presentation-request';

// ─── Policy Bridge Types ───────────────────────────────────────────

export type PolicyVerdict = 'ALLOW' | 'DENY' | 'PROMPT';

export interface ConsentContext {
    /** The parsed authorization request */
    request: AuthorizationRequest;
    /** Paths being requested (for UI display) */
    requestedPaths: string[];
    /** Whether selective disclosure is required */
    requiresSD: boolean;
    /** Verifier name from client_metadata */
    verifierName?: string;
    /** Purpose from presentation definition */
    purpose?: string;
}

export interface PolicyEvaluationInput {
    /** The presentation definition */
    definition: PresentationDefinition;
    /** Verifier client_id */
    verifierId: string;
    /** Session nonce */
    nonce: string;
    /** User's DID (for pairwise DID generation) */
    holderDid?: string;
}

export type PolicyEvaluatorFn = (input: PolicyEvaluationInput) => Promise<{
    verdict: PolicyVerdict;
    reasons: string[];
    decisionId: string;
}>;

export interface OID4VPFlowOptions {
    /** Policy evaluator function (injects policy-engine dependency) */
    evaluator: PolicyEvaluatorFn;
    /** Called when PROMPT verdict — user must explicitly grant */
    onPrompt: (ctx: ConsentContext) => Promise<boolean>;
    /** Holder DID for response building */
    holderDid: string;
    /** Selected credentials to present (filtered from wallet) */
    selectCredentials: (definition: PresentationDefinition) => Promise<string[]>;
}

export interface OID4VPFlowResult {
    verdict: PolicyVerdict;
    response?: AuthorizationResponse;
    decisionId?: string;
    error?: string;
    reasons?: string[];
}

// ─── OID4VP Consent Flow ───────────────────────────────────────────

/**
 * Execute the full OID4VP consent flow:
 * Parse → Evaluate → (Prompt?) → Build Response
 *
 * @param rawRequest Raw authorization request object (from QR/link)
 * @param opts Flow configuration including policy evaluator and credential selector
 */
export async function executeOID4VPFlow(
    rawRequest: unknown,
    opts: OID4VPFlowOptions
): Promise<OID4VPFlowResult> {
    // Step 1: Parse the authorization request
    const parseResult = parseAuthorizationRequest(rawRequest);
    if (!parseResult.ok) {
        return {
            verdict: 'DENY',
            error: parseResult.error,
            reasons: [parseResult.code],
        };
    }

    const request = parseResult.value!;
    const definition = request.presentation_definition;

    // Step 2: Build consent context for policy evaluation + UI
    const ctx: ConsentContext = {
        request,
        requestedPaths: extractRequestedPaths(definition),
        requiresSD: requiresSelectiveDisclosure(definition),
        verifierName: request.client_metadata?.client_name,
        purpose: definition.purpose,
    };

    // Step 3: Policy evaluation
    const evaluation = await opts.evaluator({
        definition,
        verifierId: request.client_id,
        nonce: request.nonce,
        holderDid: opts.holderDid,
    });

    // Step 4: Handle DENY immediately (fail-closed)
    if (evaluation.verdict === 'DENY') {
        return {
            verdict: 'DENY',
            decisionId: evaluation.decisionId,
            error: `Policy denied: ${evaluation.reasons.join(', ')}`,
            reasons: evaluation.reasons,
        };
    }

    // Step 5: Handle PROMPT — request explicit user consent
    if (evaluation.verdict === 'PROMPT') {
        const userGranted = await opts.onPrompt(ctx);
        if (!userGranted) {
            return {
                verdict: 'DENY',
                decisionId: evaluation.decisionId,
                error: 'User denied consent',
                reasons: ['USER_DENIED'],
            };
        }
    }

    // Step 6: Select credentials from wallet
    const credentials = await opts.selectCredentials(definition);
    if (credentials.length === 0) {
        return {
            verdict: 'DENY',
            decisionId: evaluation.decisionId,
            error: 'No matching credentials found',
            reasons: ['NO_MATCHING_CREDENTIALS'],
        };
    }

    // Step 7: Build the authorization response
    const buildResult = buildAuthorizationResponse({
        request,
        holder: opts.holderDid,
        consent: { granted: true, selectedCredentials: credentials },
    });

    if (!buildResult.ok) {
        return {
            verdict: 'DENY',
            decisionId: evaluation.decisionId,
            error: buildResult.error,
            reasons: [buildResult.code],
        };
    }

    return {
        verdict: 'ALLOW',
        response: buildResult.value,
        decisionId: evaluation.decisionId,
        reasons: evaluation.reasons,
    };
}

// ─── Request → Policy Input Mapper ────────────────────────────────

/**
 * Map an OID4VP authorization request to the format expected by policy evaluators.
 * This separates the OID4VP parsing layer from the policy layer.
 */
export function mapRequestToPolicyInput(request: AuthorizationRequest): PolicyEvaluationInput {
    return {
        definition: request.presentation_definition,
        verifierId: request.client_id,
        nonce: request.nonce,
    };
}

/**
 * Validate that an OID4VP request is compatible with a given set of policy constraints.
 * Used for pre-flight checks before expensive policy evaluation.
 */
export function validateRequestCompatibility(
    request: AuthorizationRequest,
    allowedVerifiers: string[],
    maxClaimsPerRequest = 10
): ValidationResult {
    const totalPaths = extractRequestedPaths(request.presentation_definition);

    if (totalPaths.length > maxClaimsPerRequest) {
        return {
            ok: false,
            error: `Request asks for ${totalPaths.length} claim paths, max is ${maxClaimsPerRequest}`,
            code: 'TOO_MANY_CLAIMS',
        };
    }

    if (allowedVerifiers.length > 0 && !allowedVerifiers.includes(request.client_id)) {
        return {
            ok: false,
            error: `Verifier ${request.client_id} not in allowlist`,
            code: 'VERIFIER_NOT_ALLOWED',
        };
    }

    return { ok: true };
}
