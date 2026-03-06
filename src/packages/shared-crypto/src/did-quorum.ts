/**
 * Spec 82 — DID Resolver Hardening v1
 * Spec 84 — Quorum Logic
 * Spec 85 — Inconsistency Detection
 * Spec 83 — Config Profiles
 *
 * Multi-resolver quorum for DID resolution. Prevents single-point manipulation.
 */

import type { DIDDocument } from '@mitch/shared-types';

// ─── Config Profiles (Spec 83) ─────────────────────────────────────

export type ResolverProfile = 'permissive' | 'balanced' | 'strict';

export interface QuorumConfig {
    /** Minimum resolvers that must agree (default: 2) */
    quorumThreshold: number;
    /** Total resolvers to query */
    resolverCount: number;
    /** Max allowed time for consensus (ms) */
    timeoutMs: number;
    /** On inconsistency: 'deny' | 'prompt' | 'use_majority' */
    onInconsistency: 'deny' | 'prompt' | 'use_majority';
    profile: ResolverProfile;
}

export const QUORUM_PROFILES: Record<ResolverProfile, QuorumConfig> = {
    permissive: {
        quorumThreshold: 1,
        resolverCount: 1,
        timeoutMs: 30_000,
        onInconsistency: 'use_majority',
        profile: 'permissive',
    },
    balanced: {
        quorumThreshold: 2,
        resolverCount: 3,
        timeoutMs: 10_000,
        onInconsistency: 'prompt',
        profile: 'balanced',
    },
    strict: {
        quorumThreshold: 3,
        resolverCount: 3,
        timeoutMs: 5_000,
        onInconsistency: 'deny',
        profile: 'strict',
    },
};

// ─── Resolver Interface ────────────────────────────────────────────

export interface DIDResolverBackend {
    name: string;
    resolve(did: string): Promise<DIDDocument>;
}

// ─── Quorum Result ─────────────────────────────────────────────────

export type QuorumDecision = 'RESOLVED' | 'INCONSISTENT' | 'INSUFFICIENT_RESOLVERS' | 'ALL_FAILED';

export interface QuorumResolutionResult {
    decision: QuorumDecision;
    document?: DIDDocument;
    inconsistency?: InconsistencyReport;
    resolvedCount: number;
    failedCount: number;
    consensusReached: boolean;
}

export interface InconsistencyReport {
    type: 'KEY_MISMATCH' | 'CONTROLLER_MISMATCH' | 'SERVICE_MISMATCH' | 'HASH_MISMATCH';
    description: string;
    resolversAgreeing: string[];
    resolversDisagreeing: string[];
}

// ─── Quorum Resolver ───────────────────────────────────────────────

/**
 * Resolve a DID via multiple resolvers and apply quorum logic.
 * Inconsistency = possible manipulation → fail-closed.
 */
export class QuorumDIDResolver {
    private readonly backends: DIDResolverBackend[];
    private readonly config: QuorumConfig;

    constructor(backends: DIDResolverBackend[], config?: Partial<QuorumConfig>) {
        this.backends = backends;
        this.config = { ...QUORUM_PROFILES.balanced, ...config };
    }

    async resolve(did: string): Promise<QuorumResolutionResult> {
        // Query all resolvers in parallel with timeout
        const results = await Promise.allSettled(
            this.backends.map(b =>
                Promise.race([
                    b.resolve(did).then(doc => ({ backend: b.name, doc })),
                    new Promise<never>((_, reject) =>
                        setTimeout(() => reject(new Error('timeout')), this.config.timeoutMs)
                    ),
                ])
            )
        );

        const resolved: Array<{ backend: string; doc: DIDDocument }> = [];
        let failedCount = 0;

        for (const r of results) {
            if (r.status === 'fulfilled') {
                resolved.push(r.value);
            } else {
                failedCount++;
            }
        }

        if (resolved.length < this.config.quorumThreshold) {
            return {
                decision: 'INSUFFICIENT_RESOLVERS',
                resolvedCount: resolved.length,
                failedCount,
                consensusReached: false,
            };
        }

        // Check consistency
        const inconsistency = this.detectInconsistency(resolved);

        if (inconsistency) {
            const quorumDecision = this.config.onInconsistency === 'use_majority'
                ? this.buildMajorityResult(resolved, inconsistency, failedCount)
                : {
                    decision: 'INCONSISTENT' as QuorumDecision,
                    inconsistency,
                    resolvedCount: resolved.length,
                    failedCount,
                    consensusReached: false,
                };
            return quorumDecision;
        }

        return {
            decision: 'RESOLVED',
            document: resolved[0].doc,
            resolvedCount: resolved.length,
            failedCount,
            consensusReached: true,
        };
    }

    /**
     * Detect inconsistencies across resolver results (Spec 85).
     */
    private detectInconsistency(
        resolved: Array<{ backend: string; doc: DIDDocument }>
    ): InconsistencyReport | null {
        if (resolved.length < 2) return null;

        const hashes = resolved.map(r => this.hashDocument(r.doc));
        const allSame = hashes.every(h => h === hashes[0]);
        if (allSame) return null;

        // Find majority hash
        const hashCounts = new Map<string, string[]>();
        for (let i = 0; i < resolved.length; i++) {
            const h = hashes[i];
            if (!hashCounts.has(h)) hashCounts.set(h, []);
            hashCounts.get(h)!.push(resolved[i].backend);
        }

        const majorityEntry = [...hashCounts.entries()].sort((a, b) => b[1].length - a[1].length)[0];
        const minorityBackends = [...hashCounts.entries()]
            .filter(([h]) => h !== majorityEntry[0])
            .flatMap(([, backends]) => backends);

        return {
            type: 'HASH_MISMATCH',
            description: `DID document hash mismatch across resolvers`,
            resolversAgreeing: majorityEntry[1],
            resolversDisagreeing: minorityBackends,
        };
    }

    private buildMajorityResult(
        resolved: Array<{ backend: string; doc: DIDDocument }>,
        inconsistency: InconsistencyReport,
        failedCount: number
    ): QuorumResolutionResult {
        // Use the document from the majority agreeing resolver
        const majorityBackend = inconsistency.resolversAgreeing[0];
        const majorityDoc = resolved.find(r => r.backend === majorityBackend)?.doc;

        if (majorityDoc && inconsistency.resolversAgreeing.length >= this.config.quorumThreshold) {
            return {
                decision: 'RESOLVED',
                document: majorityDoc,
                inconsistency,
                resolvedCount: resolved.length,
                failedCount,
                consensusReached: true,
            };
        }

        return {
            decision: 'INCONSISTENT',
            inconsistency,
            resolvedCount: resolved.length,
            failedCount,
            consensusReached: false,
        };
    }

    /**
     * Deterministic hash of a DID document for comparison.
     */
    private hashDocument(doc: DIDDocument): string {
        // Sort keys for deterministic hashing
        const canonical = JSON.stringify(doc, Object.keys(doc).sort());
        // Simple hash (not crypto-grade — just for comparison)
        let hash = 0;
        for (let i = 0; i < canonical.length; i++) {
            hash = ((hash << 5) - hash) + canonical.charCodeAt(i);
            hash |= 0;
        }
        return hash.toString(16);
    }
}
