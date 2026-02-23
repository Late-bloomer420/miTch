/**
 * @mitch/predicates - Wallet-Side Predicate Evaluation
 * 
 * Evaluates predicates locally on the wallet without leaking PII.
 * Returns only boolean results + cryptographic bindings.
 */

import {
    Predicate,
    PredicateRequest,
    PredicateClause,
    PredicateExpression,
    hashPredicateAsync,
    hashRequestAsync,
    canonicalStringify
} from './canonical';

import {
    DecisionProofPayload,
    PredicateEvaluation,
    PredicateResult
} from './types';

// ============================================================================
// COMMON PREDICATES (Helper Functions)
// ============================================================================

export const CommonPredicates = {
    /**
     * Creates a predicate requiring the user to be at least N years old.
     * @param years - Minimum age in years
     */
    ageAtLeast(years: number): Predicate {
        return {
            id: `age_gte_${years}`,
            description: `User is at least ${years} years old`,
            credentialTypes: ['VerifiableCredential'],
            expression: {
                logic: 'and' as const,
                clauses: [
                    {
                        path: 'credentialSubject.birthDate',
                        op: 'gte' as const,
                        type: 'age_years' as const,
                        value: years
                    }
                ]
            }
        };
    },

    /**
     * Creates a predicate requiring residency in one of the specified countries.
     * @param countryCodes - ISO 2-letter country codes
     */
    residesIn(countryCodes: string[]): Predicate {
        return {
            id: `residency_in_${countryCodes.join('_')}`,
            description: `User resides in one of: ${countryCodes.join(', ')}`,
            credentialTypes: ['VerifiableCredential'],
            expression: {
                logic: 'and' as const,
                clauses: [
                    {
                        path: 'credentialSubject.residency',
                        op: 'in' as const,
                        type: 'string[]' as const,
                        value: countryCodes
                    }
                ]
            }
        };
    },

    /**
     * Creates a predicate requiring residency in the EU (EEA).
     */
    euResident(): Predicate {
        const euCountries = [
            'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE',
            'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV',
            'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK',
            'SI', 'ES', 'SE'
        ];
        return {
            id: 'residency_eu',
            description: 'User is an EU resident',
            credentialTypes: ['VerifiableCredential'],
            expression: {
                logic: 'and' as const,
                clauses: [
                    {
                        path: 'credentialSubject.residency',
                        op: 'in' as const,
                        type: 'string[]' as const,
                        value: euCountries
                    }
                ]
            }
        };
    }
};

// ============================================================================
// EVALUATION ENGINE
// ============================================================================

/**
 * Result of a single predicate clause evaluation.
 */
interface ClauseResult {
    passed: boolean;
    reasonCode?: 'MISSING_PATH' | 'TYPE_MISMATCH' | 'CRITERIA_NOT_MET' | 'INVALID_PREDICATE';
}

/**
 * Calculates accurate age from a YYYY-MM-DD string, ignoring timezone shifts.
 * Treats the date as a "floating date" relative to the user's current local day.
 */
function calculateAgeFromBirthDate(birthDateStr: string): number {
    // Parse "YYYY-MM-DD" manually to avoid UTC/Local shifting
    const [year, month, day] = birthDateStr.split('T')[0].split('-').map(Number);
    if (!year || !month || !day) return 0; // Invalid format safety

    const today = new Date();
    const currentYear = today.getFullYear();
    const currentMonth = today.getMonth() + 1; // 1-indexed for comparison
    const currentDay = today.getDate();

    let age = currentYear - year;

    // Adjust if birthday hasn't occurred yet this year
    if (currentMonth < month || (currentMonth === month && currentDay < day)) {
        age--;
    }
    return age;
}

/**
 * Safely retrieves a nested value from a credential object using dot-notation.
 * Supports array indexing, e.g., "items[0].value".
 */
const ARRAY_INDEX_REGEX = /\[(\d+)\]/g;
function getValueAtPath(obj: Record<string, any>, path: string): unknown {
    // Replace array indices [0] -> .0 to canonicalize and split only once
    const normalizedPath = path.replace(ARRAY_INDEX_REGEX, '.$1');
    const parts = normalizedPath.split('.');

    let current: any = obj;
    for (const part of parts) {
        if (current && (typeof current === 'object' || Array.isArray(current)) && part in current) {
            current = current[part];
        } else {
            return undefined;
        }
    }
    return current;
}

/**
 * Evaluates a single predicate clause against a credential.
 * Handles type-specific comparisons (age, dates, numbers, strings).
 *
 * @param clause - The condition to check
 * @param credential - The data source
 * @returns Result with pass/fail status and optional failure reason
 */
function evaluateClause(clause: PredicateClause, credential: Record<string, any>): ClauseResult {
    const value = getValueAtPath(credential, clause.path);

    // Implement 'exists' operator logic
    if (clause.op === 'exists') {
        // exists: true -> value must not be undefined
        // exists: false -> value must be undefined
        const shouldExist = clause.value as boolean;
        if (shouldExist) {
            return { passed: value !== undefined, reasonCode: value !== undefined ? undefined : 'MISSING_PATH' };
        } else {
            return { passed: value === undefined, reasonCode: value === undefined ? undefined : 'CRITERIA_NOT_MET' };
        }
    }

    // Fail closed on missing path (return false, don't throw)
    if (value === undefined) {
        return { passed: false, reasonCode: 'MISSING_PATH' };
    }

    if (clause.type === 'age_years') {
        if (typeof value !== 'string') return { passed: false, reasonCode: 'TYPE_MISMATCH' };

        const birthDateStr = value;
        const age = calculateAgeFromBirthDate(birthDateStr);
        const compareValue = Number(clause.value);

        let passed: boolean;
        switch (clause.op) {
            case 'gte':
                passed = age >= compareValue;
                break;
            case 'gt':
                passed = age > compareValue;
                break;
            case 'lte':
                passed = age <= compareValue;
                break;
            case 'lt':
                passed = age < compareValue;
                break;
            case 'eq':
                passed = age === compareValue;
                break;
            default:
                return { passed: false, reasonCode: 'INVALID_PREDICATE' };
        }
        return { passed, reasonCode: passed ? undefined : 'CRITERIA_NOT_MET' };
    }

    if (clause.type === 'string') {
        // Strict type check or lenient string conversion? 
        // Best practice: Be strict if schema implies string type.
        // But for robustness, we cast to string if present.
        const strValue = String(value);

        let passed: boolean;
        switch (clause.op) {
            case 'eq':
                passed = strValue === String(clause.value);
                break;
            case 'neq':
                passed = strValue !== String(clause.value);
                break;
            default:
                // String type (scalar) does not support in/nin on array of values (use string[] type for that)
                return { passed: false, reasonCode: 'INVALID_PREDICATE' };
        }
        return { passed, reasonCode: passed ? undefined : 'CRITERIA_NOT_MET' };
    }

    if (clause.type === 'string[]') {
        const strValue = String(value);

        // This predicate expects a set of allowed values in clause.value
        if (!Array.isArray(clause.value)) {
            return { passed: false, reasonCode: 'INVALID_PREDICATE' };
        }

        let passed: boolean;
        switch (clause.op) {
            case 'in':
                passed = (clause.value as string[]).includes(strValue);
                break;
            case 'nin':
                passed = !(clause.value as string[]).includes(strValue);
                break;
            default:
                return { passed: false, reasonCode: 'INVALID_PREDICATE' };
        }
        return { passed, reasonCode: passed ? undefined : 'CRITERIA_NOT_MET' };
    }

    if (clause.type === 'boolean') {
        const boolValue = Boolean(value);
        const compareValue = Boolean(clause.value);

        let passed: boolean;
        if (clause.op === 'eq') {
            passed = boolValue === compareValue;
        } else if (clause.op === 'neq') {
            passed = boolValue !== compareValue;
        } else {
            return { passed: false, reasonCode: 'INVALID_PREDICATE' };
        }
        return { passed, reasonCode: passed ? undefined : 'CRITERIA_NOT_MET' };
    }

    if (clause.type === 'number') {
        if (typeof value !== 'number' && typeof value !== 'string') return { passed: false, reasonCode: 'TYPE_MISMATCH' };

        const numValue = Number(value);
        if (isNaN(numValue)) return { passed: false, reasonCode: 'TYPE_MISMATCH' };

        const compareValue = Number(clause.value);

        let passed: boolean;
        switch (clause.op) {
            case 'eq':
                passed = numValue === compareValue;
                break;
            case 'gt':
                passed = numValue > compareValue;
                break;
            case 'gte':
                passed = numValue >= compareValue;
                break;
            case 'lt':
                passed = numValue < compareValue;
                break;
            case 'lte':
                passed = numValue <= compareValue;
                break;
            default:
                return { passed: false, reasonCode: 'INVALID_PREDICATE' };
        }
        return { passed, reasonCode: passed ? undefined : 'CRITERIA_NOT_MET' };
    }

    return { passed: false, reasonCode: 'TYPE_MISMATCH' };
}

/**
 * Recursively evaluates a predicate expression tree (AND/OR logic).
 *
 * @param expr - The expression containing clauses or sub-expressions
 * @param credential - The data source
 * @returns Aggregated result
 */
function evaluateExpression(expr: PredicateExpression, credential: Record<string, any>): ClauseResult {
    const results = expr.clauses.map(clause => {
        if ('logic' in clause) {
            return evaluateExpression(clause as PredicateExpression, credential);
        }
        return evaluateClause(clause as PredicateClause, credential);
    });

    if (expr.logic === 'and') {
        // All must pass - return first failure
        for (const r of results) {
            if (!r.passed) {
                return r;
            }
        }
        return { passed: true };
    }
    if (expr.logic === 'or') {
        // At least one must pass
        for (const r of results) {
            if (r.passed) {
                return { passed: true };
            }
        }
        return results[0] || { passed: false, reasonCode: 'CRITERIA_NOT_MET' };
    }

    return { passed: false, reasonCode: 'INVALID_PREDICATE' };
}

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Evaluate predicates locally (wallet-side, device-only).
 * Returns only boolean results, never raw PII.
 */
export async function evaluatePredicates(
    credential: Record<string, any>,
    request: PredicateRequest,
    signFn: (data: string) => Promise<string>
): Promise<PredicateResult> {
    // Security: Verify required fields
    if (!request.verifierDid || !request.nonce) {
        throw new Error('SECURITY_VIOLATION: Missing verifierDid or nonce');
    }

    // Convert predicate strings/objects to canonical form
    const predicates = request.predicates.map(p => {
        if (typeof p === 'string') {
            throw new Error('String predicate IDs not yet supported');
        }
        return p;
    });

    // Evaluate each predicate
    const evaluations: PredicateEvaluation[] = [];
    let allPassed = true;

    for (const pred of predicates) {
        const result = evaluateExpression(pred.expression, credential);
        const predicateHash = await hashPredicateAsync(pred);

        evaluations.push({
            predicateId: pred.id,
            predicateHash,
            result: result.passed,
            reasonCode: result.reasonCode
        });

        if (!result.passed) {
            allPassed = false;
        }
    }

    // Create decision ID and timestamp
    const decisionId = `decision_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    const evaluatedAt = request.timestamp || new Date().toISOString();

    // Compute request hash
    const requestHash = await hashRequestAsync(request);

    // Build binding (cryptographic proof) - This is the canonical payload
    const proofPayload: DecisionProofPayload = {
        decisionId,
        evaluatedAt,
        allPassed,
        evaluations,
        binding: {
            requestHash,
            verifierDid: request.verifierDid,
            nonce: request.nonce,
            evidenceCommitment: undefined
        }
    };

    // Sign the payload
    // Use canonical stringify for deterministic signing
    const payloadString = canonicalStringify(proofPayload);
    const signature = await signFn(payloadString);

    return {
        proof: proofPayload,
        signature
    };
}
