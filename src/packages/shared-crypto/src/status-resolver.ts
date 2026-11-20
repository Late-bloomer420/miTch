/**
 * Status List Resolver for SD-JWT VC
 * Wires @askmi/revocation-statuslist into the shared-crypto suite.
 */

import { StatusListRevocationChecker } from '@askmi/revocation-statuslist';
import type {
    StatusListEntry,
    RevocationCheckResult,
    RiskTier,
    StatusListKeyResolver,
    StatusListMode,
} from '@askmi/revocation-statuslist';
import type { StatusClaim } from './sd-jwt-vc.js';

/**
 * High-level resolver for SD-JWT VC status claims.
 */
export class SDJWTStatusResolver {
    private checker: StatusListRevocationChecker;
    private readonly statusListMode: StatusListMode | undefined;
    private resolveStatusListKey: StatusListKeyResolver | undefined;

    /**
     * API-05: outside `ASKMI_TRUST_MODE=dev` (or `statusListMode: 'dev'`) a status list must
     * be a signed VC-JWT whose issuer key `resolveStatusListKey` returns; otherwise the
     * revocation check fails closed.
     */
    constructor(options?: {
        fetchFn?: typeof fetch;
        statusListMode?: StatusListMode;
        resolveStatusListKey?: StatusListKeyResolver;
    }) {
        this.statusListMode = options?.statusListMode;
        this.resolveStatusListKey = options?.resolveStatusListKey;
        this.checker = this.createChecker(options?.fetchFn);
    }

    private createChecker(fetchFn: typeof fetch | undefined): StatusListRevocationChecker {
        return new StatusListRevocationChecker({
            fetchFn,
            cacheTtlMs: 10 * 60 * 1000, // 10 minutes
            statusListMode: this.statusListMode,
            resolveStatusListKey: this.resolveStatusListKey,
        });
    }

    /**
     * Update the fetch function used by the underlying checker.
     * Useful for testing environments where fetch is stubbed after module load.
     */
    setFetch(fetchFn: typeof fetch): void {
        this.checker = this.createChecker(fetchFn);
    }

    /** Wire the status-list issuer key resolver (e.g. the verifier's trusted-issuer JWKS). */
    setStatusListKeyResolver(resolver: StatusListKeyResolver | undefined): void {
        this.resolveStatusListKey = resolver;
        this.checker.setStatusListKeyResolver(resolver);
    }

    /**
     * Resolve a status claim and check for revocation.
     * 
     * @param status - The status claim from the SD-JWT VC
     * @param riskTier - 'high' (fail-closed, no grace) or 'low'
     */
    async checkStatus(
        status: StatusClaim,
        riskTier: RiskTier = 'high'
    ): Promise<RevocationCheckResult> {
        // Map SD-JWT VC status_list to StatusList2021Entry
        const entry: StatusListEntry = {
            id: status.status_list.uri, // Using URI as ID for PoC
            type: 'StatusList2021Entry',
            statusPurpose: 'revocation',
            statusListIndex: status.status_list.idx.toString(),
            statusListCredential: status.status_list.uri,
        };

        return this.checker.checkRevocation(entry, riskTier);
    }
}

/**
 * Global singleton for shared use.
 */
export const statusResolver = new SDJWTStatusResolver();
