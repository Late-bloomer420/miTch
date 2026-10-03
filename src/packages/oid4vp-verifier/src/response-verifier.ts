/**
 * OID4VP Verifier — Response validation
 */

import type { AuthorizationResponse, PresentationDefinition, ValidationResult } from '@askmi/oid4vp';
import { validateSubmission, parseVPToken } from '@askmi/oid4vp';
import {
    validateSDJWTVC,
    validateKeyBindingJWT,
} from '@askmi/shared-crypto';

// The JWK type originates in jose (a transitive dependency via @askmi/shared-crypto).
// We re-derive the holder-key union from the public API of validateKeyBindingJWT so
// we do not need to add jose as a direct devDependency.
type IssuerOrHolderKey = Parameters<typeof validateKeyBindingJWT>[1];

// ─── Nonce Store (in-memory, replace with persistent store in prod) ─

const usedNonces = new Map<string, number>(); // nonce → timestamp

/**
 * Check nonce has not been replayed.
 * TTL is 5 minutes.
 */
function checkNonce(nonce: string): boolean {
    const now = Date.now();
    // Purge expired
    for (const [n, ts] of usedNonces) {
        if (now - ts > 5 * 60 * 1000) usedNonces.delete(n);
    }
    if (usedNonces.has(nonce)) return false;
    usedNonces.set(nonce, now);
    return true;
}

// ─── Response Verifier ─────────────────────────────────────────────

export interface VerifyResponseOptions {
    response: AuthorizationResponse;
    expectedNonce: string;
    expectedState?: string;
    definition: PresentationDefinition;
    skipNonceCheck?: boolean; // for testing only
    // NEW — cryptographic verification (opt-in; default off preserves structural behaviour)
    verifyCredentialSignatures?: boolean;
    resolveIssuerKey?: (iss: string) => Promise<IssuerOrHolderKey | null>;
    expectedAudience?: string; // verifier client_id, for KB-JWT aud binding
}

export interface VerificationResult {
    valid: boolean;
    credentials: string[];
    errors: string[];
    signaturesVerified: boolean; // NEW — never let a caller be misled about whether crypto ran
}

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 * Returns null on any decoding failure.
 */
function decodeBase64url(input: string): string | null {
    try {
        // Restore standard base64 padding/chars
        const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
        return atob(padded);
    } catch {
        return null;
    }
}

/**
 * Extract the `iss` claim from the first part of a compact SD-JWT VC
 * (the issuer JWT, before the first `~`). Does NOT verify the signature.
 * Returns null if the payload cannot be decoded or `iss` is absent.
 */
function extractIssFromSDJWT(credential: string): string | null {
    // SD-JWT format: <issuerJwt>~<disc1>~...~[kbJwt]
    const jwtPart = credential.split('~')[0];
    const segments = jwtPart.split('.');
    if (segments.length < 3) return null;
    const payloadJson = decodeBase64url(segments[1]);
    if (payloadJson === null) return null;
    try {
        const payload = JSON.parse(payloadJson) as Record<string, unknown>;
        const iss = payload['iss'];
        return typeof iss === 'string' && iss.length > 0 ? iss : null;
    } catch {
        return null;
    }
}

/**
 * Return true when `segment` looks like a compact JWT (contains exactly two dots).
 */
function isCompactJWT(segment: string): boolean {
    return segment.split('.').length === 3;
}

/**
 * Verify an OID4VP Authorization Response.
 * Checks: nonce, state, submission matches definition, credential count.
 * Optionally (step 6) verifies cryptographic issuer signatures and KB-JWTs.
 */
export async function verifyAuthorizationResponse(
    opts: VerifyResponseOptions
): Promise<VerificationResult> {
    const {
        response,
        expectedNonce,
        expectedState,
        definition,
        skipNonceCheck,
        verifyCredentialSignatures,
        resolveIssuerKey,
        expectedAudience,
    } = opts;
    const errors: string[] = [];

    // 1. Nonce check
    if (!skipNonceCheck && !checkNonce(expectedNonce)) {
        errors.push('Nonce replay detected');
    }

    // 2. State check
    if (expectedState && response.state !== expectedState) {
        errors.push(`State mismatch: expected ${expectedState}, got ${response.state}`);
    }

    // 3. Submission check
    const submissionResult = validateSubmission(response.presentation_submission, definition);
    if (!submissionResult.valid) {
        errors.push(...submissionResult.errors);
    }

    // 4. VP Token parse
    const { credentials } = parseVPToken(response.vp_token);
    const nonEmptyCredentials = credentials.filter(c => c.length > 0);
    if (nonEmptyCredentials.length === 0) {
        errors.push('VP Token contains no credentials');
    }

    // 5. Descriptor count matches credentials
    const descriptorCount = definition.input_descriptors.length;
    if (nonEmptyCredentials.length < descriptorCount) {
        errors.push(
            `Credential count mismatch: expected ≥${descriptorCount}, got ${nonEmptyCredentials.length}`
        );
    }

    // 6. Cryptographic verification (only when opts.verifyCredentialSignatures === true)
    let signaturesVerified = false;

    if (verifyCredentialSignatures) {
        if (!resolveIssuerKey) {
            // Fail-closed: requested but no resolver provided
            errors.push(
                'signature verification requested but no issuer key resolver provided'
            );
        } else {
            let allPassed = nonEmptyCredentials.length > 0;

            for (const credential of nonEmptyCredentials) {
                // a. Decode issuer-JWT payload (WITHOUT verifying) to read `iss`
                const iss = extractIssFromSDJWT(credential);
                if (iss === null) {
                    errors.push(
                        `Cannot decode issuer JWT payload for credential (unknown format)`
                    );
                    allPassed = false;
                    continue;
                }

                // b–d. Per-credential crypto work: catch ALL thrown exceptions fail-closed.
                // Any exception from resolveIssuerKey, validateSDJWTVC, or validateKeyBindingJWT
                // is converted to an error entry rather than propagating out of the function.
                let credPassed = true;
                try {
                    // b. Resolve issuer key
                    const issuerKey = await resolveIssuerKey(iss);
                    if (issuerKey === null) {
                        errors.push(`no key for issuer ${iss}`);
                        credPassed = false;
                    } else {
                        // c. Verify issuer signature via validateSDJWTVC
                        const vcResult = await validateSDJWTVC(credential, issuerKey);
                        if (!vcResult.ok) {
                            errors.push(...vcResult.errors);
                            credPassed = false;
                        } else {
                            // d. KB-JWT verification if present
                            // SD-JWT format: <issuerJwt>~[disc1~disc2~...]~[kbJwt]
                            // Split on '~', last segment is KB-JWT candidate if it looks like a JWT
                            const parts = credential.split('~');
                            // parts[0] = issuerJwt, parts[1..n-2] = disclosures, parts[n-1] = kbJwt or ''
                            const lastSegment = parts[parts.length - 1];
                            if (lastSegment.length > 0 && isCompactJWT(lastSegment)) {
                                const kbJwt = lastSegment;
                                // sdJwtWithDisclosures = everything before the final kbJwt segment
                                // i.e. parts[0]~parts[1]~...~parts[n-2]~ (with trailing tilde)
                                const sdJwtWithDisclosures = parts.slice(0, parts.length - 1).join('~') + '~';

                                // Fail-closed: KB-JWT aud binding requires expectedAudience to be set.
                                if (!expectedAudience) {
                                    errors.push(
                                        'KB-JWT present but no expectedAudience configured for aud binding'
                                    );
                                    credPassed = false;
                                } else {
                                    // Use the cnf.jwk directly from the verified SD-JWT VC payload.
                                    // extractCNFPublicKey returns a platform key type (CryptoKey / KeyObject)
                                    // which may not be instanceof CryptoKey in Node.js; using the JWK avoids
                                    // the platform-key-type ambiguity inside validateKeyBindingJWT.
                                    const cnfJwk = vcResult.payload!.cnf?.jwk;
                                    if (!cnfJwk) {
                                        errors.push(
                                            `KB-JWT present but no cnf.jwk in SD-JWT VC payload for issuer ${iss}`
                                        );
                                        credPassed = false;
                                    } else {
                                        const kbResult = await validateKeyBindingJWT(
                                            kbJwt,
                                            cnfJwk as IssuerOrHolderKey,
                                            {
                                                expectedAud: expectedAudience,
                                                expectedNonce,
                                                sdJwtWithDisclosures,
                                            }
                                        );
                                        if (!kbResult.ok) {
                                            errors.push(...kbResult.errors);
                                            credPassed = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (err: unknown) {
                    // Any thrown exception from resolveIssuerKey / validateSDJWTVC /
                    // validateKeyBindingJWT is caught here and converted to a fail-closed error.
                    const msg = err instanceof Error ? err.message : String(err);
                    errors.push(`${iss} crypto verification error: ${msg}`);
                    credPassed = false;
                }
                if (!credPassed) {
                    allPassed = false;
                    continue;
                }
            }

            signaturesVerified = allPassed;
        }
    }

    return {
        valid: errors.length === 0,
        credentials: nonEmptyCredentials,
        errors,
        signaturesVerified,
    };
}

/**
 * Verify that a presented credential satisfies a field constraint.
 * Simplified: checks that the credential string is non-empty (real impl
 * would decode SD-JWT and verify field paths).
 */
export function satisfiesConstraints(
    credential: string,
    definition: PresentationDefinition
): ValidationResult {
    if (!credential || credential.length < 10) {
        return { ok: false, error: 'Credential too short to be valid', code: 'INVALID_CREDENTIAL' };
    }

    // Check all input descriptors have a corresponding entry
    for (const desc of definition.input_descriptors) {
        if (desc.constraints?.fields) {
            for (const field of desc.constraints.fields) {
                if (!field.optional && field.path.length === 0) {
                    return { ok: false, error: `Empty path in descriptor ${desc.id}`, code: 'EMPTY_PATH' };
                }
            }
        }
    }

    return { ok: true };
}
