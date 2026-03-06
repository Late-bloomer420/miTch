/**
 * Jurisdiction Compatibility Gate (Specs 60-61)
 *
 * Country/region-based policy rules, GDPR adequacy decisions,
 * and geo-scope combination for EHDS compliance.
 */

// ─── Types ─────────────────────────────────────────────────────────

export type JurisdictionCode = string; // ISO 3166-1 alpha-2

export interface JurisdictionRule {
    /** ISO 3166-1 alpha-2 or region code like 'EU' */
    jurisdiction: JurisdictionCode;
    /** Whether this jurisdiction is allowed at all */
    allowed: boolean;
    /** Minimum consent level required */
    minConsentLevel?: 'explicit' | 'informed' | 'implicit';
    /** Whether GDPR applies */
    gdprApplies?: boolean;
    /** GDPR adequacy decision (Art. 45): 'adequate' | 'not_adequate' | 'unknown' */
    gdprAdequacy?: 'adequate' | 'not_adequate' | 'unknown';
    /** Data transfer restrictions */
    dataTransferRestrictions?: string[];
}

export interface JurisdictionGateResult {
    allowed: boolean;
    reason?: string;
    code?: string;
    requiredConsentLevel?: string;
}

// ─── GDPR Adequacy Decisions (Art. 45) ─────────────────────────────

/** Countries with GDPR adequacy decisions as of 2024 */
export const GDPR_ADEQUATE_COUNTRIES = new Set([
    'AD', 'AR', 'CA', 'FO', 'GB', 'GG', 'IL', 'IM', 'JP', 'JE',
    'NZ', 'CH', 'UY', 'KR', 'US', // US: Data Privacy Framework
]);

/** EU/EEA member states */
export const JURISDICTION_EU_EEA = new Set([
    'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI',
    'FR', 'GR', 'HR', 'HU', 'IE', 'IS', 'IT', 'LI', 'LT', 'LU',
    'LV', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK',
]);

// ─── Jurisdiction Gate ─────────────────────────────────────────────

export class JurisdictionGate {
    private readonly rules: Map<string, JurisdictionRule>;
    private readonly defaultAllowed: boolean;

    constructor(rules: JurisdictionRule[] = [], defaultAllowed = false) {
        this.rules = new Map(rules.map(r => [r.jurisdiction, r]));
        this.defaultAllowed = defaultAllowed;
    }

    /**
     * Check if an operation is allowed for a given jurisdiction.
     */
    check(jurisdiction: JurisdictionCode, _purpose?: string): JurisdictionGateResult {
        // EU/EEA is always allowed (home jurisdiction)
        if (JURISDICTION_EU_EEA.has(jurisdiction)) {
            return { allowed: true };
        }

        // Check explicit rules
        const rule = this.rules.get(jurisdiction);
        if (rule) {
            if (!rule.allowed) {
                return {
                    allowed: false,
                    reason: `Jurisdiction ${jurisdiction} explicitly blocked`,
                    code: 'JURISDICTION_BLOCKED',
                };
            }
            return {
                allowed: true,
                requiredConsentLevel: rule.minConsentLevel,
            };
        }

        // Default behavior
        if (!this.defaultAllowed) {
            return {
                allowed: false,
                reason: `Jurisdiction ${jurisdiction} not in allowlist`,
                code: 'JURISDICTION_NOT_ALLOWED',
            };
        }

        return { allowed: true };
    }

    /**
     * Check GDPR data transfer compatibility.
     * Returns whether data can be transferred to the target jurisdiction.
     */
    checkGDPRDataTransfer(targetJurisdiction: JurisdictionCode): {
        allowed: boolean;
        mechanism?: string;
        reason?: string;
    } {
        // EU/EEA: always fine
        if (JURISDICTION_EU_EEA.has(targetJurisdiction)) {
            return { allowed: true, mechanism: 'same_jurisdiction' };
        }

        // Adequacy decision
        if (GDPR_ADEQUATE_COUNTRIES.has(targetJurisdiction)) {
            return { allowed: true, mechanism: 'adequacy_decision' };
        }

        // Not adequate — needs SCCs or BCRs (not implemented here)
        return {
            allowed: false,
            reason: `No GDPR adequacy decision for ${targetJurisdiction}. Requires SCCs or BCRs.`,
        };
    }

    /**
     * Get GDPR applicability for a jurisdiction.
     */
    getGDPRStatus(jurisdiction: JurisdictionCode): {
        applies: boolean;
        adequacy: 'adequate' | 'not_adequate' | 'eu_member' | 'unknown';
    } {
        if (JURISDICTION_EU_EEA.has(jurisdiction)) {
            return { applies: true, adequacy: 'eu_member' };
        }
        if (GDPR_ADEQUATE_COUNTRIES.has(jurisdiction)) {
            return { applies: false, adequacy: 'adequate' };
        }
        return { applies: false, adequacy: 'unknown' };
    }

    /**
     * Validate a jurisdiction code format.
     */
    static isValidCode(code: string): boolean {
        return /^[A-Z]{2}$/.test(code) || code === 'EU' || code === 'EEA';
    }

    /**
     * Combine with geo-scope from EHDS (T-A4).
     * Returns intersection of allowed jurisdictions.
     */
    intersectWithGeoScope(allowedCountries: JurisdictionCode[]): JurisdictionCode[] {
        return allowedCountries.filter(c => this.check(c).allowed);
    }
}
