/**
 * Spec 93 — Post-Quantum Readiness: Crypto Agility
 *
 * Algorithm registry, negotiation, and migration path.
 * Enables seamless transition from classical to post-quantum algorithms.
 */

// ─── Algorithm Registry ────────────────────────────────────────────

export type AlgorithmCategory = 'signing' | 'key-agreement' | 'encryption' | 'hash';
export type AlgorithmStatus = 'active' | 'deprecated' | 'pqc-candidate' | 'experimental';

export interface AlgorithmEntry {
    id: string;                    // e.g., 'ES256', 'ML-DSA-44', 'CRYSTALS-Kyber'
    category: AlgorithmCategory;
    status: AlgorithmStatus;
    /** NIST security level (1=128-bit, 3=192-bit, 5=256-bit) */
    securityLevel: 1 | 3 | 5;
    /** Post-quantum resistant */
    pqcReady: boolean;
    /** Migration target (for deprecated algorithms) */
    replacedBy?: string;
    /** Priority for negotiation (higher = preferred) */
    priority: number;
}

/** Default algorithm registry */
export const ALGORITHM_REGISTRY: AlgorithmEntry[] = [
    // Classical signing
    { id: 'ES256', category: 'signing', status: 'active', securityLevel: 1, pqcReady: false, priority: 80 },
    { id: 'ES384', category: 'signing', status: 'active', securityLevel: 3, pqcReady: false, priority: 70 },
    { id: 'ES512', category: 'signing', status: 'active', securityLevel: 5, pqcReady: false, priority: 60 },
    { id: 'RS256', category: 'signing', status: 'deprecated', securityLevel: 1, pqcReady: false, replacedBy: 'ES256', priority: 20 },
    // Post-quantum candidates (NIST 2024)
    { id: 'ML-DSA-44', category: 'signing', status: 'pqc-candidate', securityLevel: 1, pqcReady: true, priority: 95 },
    { id: 'ML-DSA-65', category: 'signing', status: 'pqc-candidate', securityLevel: 3, pqcReady: true, priority: 90 },
    { id: 'ML-DSA-87', category: 'signing', status: 'pqc-candidate', securityLevel: 5, pqcReady: true, priority: 85 },
    { id: 'SLH-DSA-SHA2-128s', category: 'signing', status: 'pqc-candidate', securityLevel: 1, pqcReady: true, priority: 75 },
    // Hybrid: classical + PQC
    { id: 'ES256+ML-DSA-44', category: 'signing', status: 'experimental', securityLevel: 1, pqcReady: true, priority: 99 },
    // Key agreement
    { id: 'ECDH-ES', category: 'key-agreement', status: 'active', securityLevel: 1, pqcReady: false, priority: 80 },
    { id: 'ML-KEM-512', category: 'key-agreement', status: 'pqc-candidate', securityLevel: 1, pqcReady: true, priority: 90 },
    { id: 'ML-KEM-768', category: 'key-agreement', status: 'pqc-candidate', securityLevel: 3, pqcReady: true, priority: 85 },
    // Encryption
    { id: 'A256GCM', category: 'encryption', status: 'active', securityLevel: 1, pqcReady: true, priority: 90 },
    { id: 'A128GCM', category: 'encryption', status: 'active', securityLevel: 1, pqcReady: true, priority: 70 },
    // Hash
    { id: 'SHA-256', category: 'hash', status: 'active', securityLevel: 1, pqcReady: false, priority: 80 },
    { id: 'SHA-384', category: 'hash', status: 'active', securityLevel: 3, pqcReady: false, priority: 85 },
    { id: 'SHA3-256', category: 'hash', status: 'active', securityLevel: 1, pqcReady: true, priority: 90 },
];

// ─── Algorithm Negotiation ─────────────────────────────────────────

export interface NegotiationRequest {
    category: AlgorithmCategory;
    /** Algorithms supported by the requesting party */
    supported: string[];
    /** Whether post-quantum algorithms are required */
    requirePQC?: boolean;
    /** Minimum security level (default: 1) */
    minSecurityLevel?: 1 | 3 | 5;
}

export type NegotiationResult =
    | { ok: true; algorithm: AlgorithmEntry; negotiated: string }
    | { ok: false; reason: string; code: string };

/**
 * Negotiate the best common algorithm between parties.
 * Prioritizes PQC-ready algorithms when required.
 */
export function negotiateAlgorithm(
    request: NegotiationRequest,
    registry: AlgorithmEntry[] = ALGORITHM_REGISTRY
): NegotiationResult {
    const candidates = registry.filter(entry => {
        if (entry.category !== request.category) return false;
        if (!request.supported.includes(entry.id)) return false;
        if (entry.status === 'deprecated') return false;
        if (request.requirePQC && !entry.pqcReady) return false;
        const minLevel = request.minSecurityLevel ?? 1;
        if (entry.securityLevel < minLevel) return false;
        return true;
    });

    if (candidates.length === 0) {
        if (request.requirePQC) {
            return {
                ok: false,
                reason: `No PQC-ready algorithm found for ${request.category} among: ${request.supported.join(', ')}`,
                code: 'NO_PQC_ALGORITHM',
            };
        }
        return {
            ok: false,
            reason: `No compatible algorithm for ${request.category}`,
            code: 'NO_COMPATIBLE_ALGORITHM',
        };
    }

    // Sort by priority (highest first)
    const best = candidates.sort((a, b) => b.priority - a.priority)[0];
    return { ok: true, algorithm: best, negotiated: best.id };
}

// ─── Migration Path ────────────────────────────────────────────────

export interface MigrationPlan {
    current: string;
    target: string;
    steps: string[];
    urgency: 'immediate' | 'planned' | 'monitor';
}

/**
 * Get migration plan for a deprecated or non-PQC algorithm.
 */
export function getMigrationPlan(
    algorithmId: string,
    registry: AlgorithmEntry[] = ALGORITHM_REGISTRY
): MigrationPlan | null {
    const entry = registry.find(e => e.id === algorithmId);
    if (!entry) return null;

    if (entry.status === 'active' && !entry.pqcReady) {
        // Find PQC replacement in same category
        const pqcAlternative = registry
            .filter(e => e.category === entry.category && e.pqcReady && e.status !== 'deprecated')
            .sort((a, b) => b.priority - a.priority)[0];

        return {
            current: algorithmId,
            target: pqcAlternative?.id ?? 'TBD',
            steps: [
                `1. Add support for ${pqcAlternative?.id ?? 'PQC algorithm'}`,
                `2. Negotiate ${pqcAlternative?.id ?? 'PQC'} with new clients`,
                `3. Migrate existing keys/certs`,
                `4. Deprecate ${algorithmId}`,
            ],
            urgency: 'planned',
        };
    }

    if (entry.status === 'deprecated') {
        return {
            current: algorithmId,
            target: entry.replacedBy ?? 'unknown',
            steps: [
                `URGENT: Migrate from deprecated ${algorithmId} to ${entry.replacedBy ?? 'supported algorithm'}`,
                `Update all key materials`,
                `Rotate credentials`,
            ],
            urgency: 'immediate',
        };
    }

    return null; // Already PQC-ready or experimental
}

// ─── Crypto Profile ────────────────────────────────────────────────

export interface CryptoProfile {
    name: 'classical' | 'hybrid' | 'pqc-only';
    signingAlgorithm: string;
    keyAgreementAlgorithm: string;
    encryptionAlgorithm: string;
    hashAlgorithm: string;
}

export const CRYPTO_PROFILES: Record<CryptoProfile['name'], CryptoProfile> = {
    classical: {
        name: 'classical',
        signingAlgorithm: 'ES256',
        keyAgreementAlgorithm: 'ECDH-ES',
        encryptionAlgorithm: 'A256GCM',
        hashAlgorithm: 'SHA-256',
    },
    hybrid: {
        name: 'hybrid',
        signingAlgorithm: 'ES256+ML-DSA-44',
        keyAgreementAlgorithm: 'ML-KEM-768',
        encryptionAlgorithm: 'A256GCM',
        hashAlgorithm: 'SHA3-256',
    },
    'pqc-only': {
        name: 'pqc-only',
        signingAlgorithm: 'ML-DSA-65',
        keyAgreementAlgorithm: 'ML-KEM-768',
        encryptionAlgorithm: 'A256GCM',
        hashAlgorithm: 'SHA3-256',
    },
};
