/**
 * Status List Resolver for SD-JWT VC
 * Wires @mitch/revocation-statuslist into the shared-crypto suite.
 */

import { StatusListRevocationChecker } from '@mitch/revocation-statuslist';
import type { StatusListEntry, RevocationCheckResult, RiskTier } from '@mitch/revocation-statuslist/src/types';
import type { StatusClaim } from './sd-jwt-vc';

/**
 * High-level resolver for SD-JWT VC status claims.
 */
export class SDJWTStatusResolver {
    private checker: StatusListRevocationChecker;

    constructor(options?: { fetchFn?: typeof fetch }) {
        this.checker = new StatusListRevocationChecker({
            fetchFn: options?.fetchFn,
            cacheTtlMs: 10 * 60 * 1000, // 10 minutes
        });
    }

    /**
     * Update the fetch function used by the underlying checker.
     * Useful for testing environments where fetch is stubbed after module load.
     */
    setFetch(fetchFn: typeof fetch): void {
        // Re-initialize checker with new fetchFn
        this.checker = new StatusListRevocationChecker({
            fetchFn,
            cacheTtlMs: 10 * 60 * 1000,
        });
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
