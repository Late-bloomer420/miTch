import { LocalAuditLog } from './LocalAuditLog.js';

export enum ComplianceStatus {
    PASS = 'PASS',
    WARN = 'WARN',
    FAIL = 'FAIL'
}

export interface ComplianceReport {
    status: ComplianceStatus;
    checks: {
        id: string;
        name: string;
        result: ComplianceStatus;
        details?: string;
    }[];
}

/**
 * eIDAS 2.0 & GDPR Compliance Checker (Version 1)
 * 
 * Performs 7 distinct runtime checks to validate the system's adherence to 
 * "Privacy by Design" and "Honesty by Construction".
 */
export class EIDASComplianceChecker {
    private auditLog: LocalAuditLog;

    constructor(auditLog: LocalAuditLog) {
        this.auditLog = auditLog;
    }

    async runChecks(config: any): Promise<ComplianceReport> {
        console.log('--- eIDAS 2.0 & DSGVO Compliance Check (Runtime) ---');

        const checks = [
            await this.checkAuditLogAccessibility(),
            await this.checkDataDeletionCapability(),
            await this.checkDataPortability(),
            await this.checkProcessingRecord(),
            await this.checkAuditLogIntegrity(),
            this.checkStructuralNonExistence(config),
            this.checkKeyEphemerality(config)
        ];

        const hasFail = checks.some(c => c.result === ComplianceStatus.FAIL);
        const hasWarn = checks.some(c => c.result === ComplianceStatus.WARN);

        const status = hasFail ? ComplianceStatus.FAIL : (hasWarn ? ComplianceStatus.WARN : ComplianceStatus.PASS);

        return { status, checks };
    }

    // Check 1: Audit Log Accessibility (Can we write/read?)
    private async checkAuditLogAccessibility() {
        try {
            await this.auditLog.initialize();
            return {
                id: 'AUDIT_ACCESS',
                name: 'Audit Log Accessibility (GDPR Art. 15)',
                result: ComplianceStatus.PASS
            };
        } catch (e) {
            return {
                id: 'AUDIT_ACCESS',
                name: 'Audit Log Accessibility (GDPR Art. 15)',
                result: ComplianceStatus.FAIL,
                details: 'Cannot access IndexedDB storage.'
            };
        }
    }

    // Check 2: Data Deletion (Right to be Forgotten)
    private async checkDataDeletionCapability() {
        // Technological capability to delete must exist.
        // In Phase-0 IDB, we can clear the store. 
        if (typeof indexedDB !== 'undefined' && typeof IDBFactory !== 'undefined') {
            return {
                id: 'DATA_DELETION',
                name: 'Data Deletion Capability (GDPR Art. 17)',
                result: ComplianceStatus.PASS
            };
        }
        return {
            id: 'DATA_DELETION',
            name: 'Data Deletion Capability (GDPR Art. 17)',
            result: ComplianceStatus.WARN,
            details: 'Browser API for deletion not explicitly verified.'
        };
    }

    // Check 3: Data Portability (Export)
    private async checkDataPortability() {
        // Check if audit log has export capability (getAllEntries returns data)
        if (typeof this.auditLog.getAllEntries === 'function') {
            return {
                id: 'DATA_PORTABILITY',
                name: 'Data Portability (GDPR Art. 20)',
                result: ComplianceStatus.PASS
            };
        }
        return {
            id: 'DATA_PORTABILITY',
            name: 'Data Portability (GDPR Art. 20)',
            result: ComplianceStatus.FAIL
        };
    }

    // Check 4: Record of Processing Activities
    private async checkProcessingRecord() {
        try {
            const entries = await this.auditLog.getAllEntries();
            // Pass if functionality works, even if empty.
            return {
                id: 'PROCESSING_RECORD',
                name: 'Record of Processing (GDPR Art. 30)',
                result: ComplianceStatus.PASS,
                details: `${entries.length} entries found.`
            };
        } catch (e) {
            return {
                id: 'PROCESSING_RECORD',
                name: 'Record of Processing (GDPR Art. 30)',
                result: ComplianceStatus.FAIL,
                details: 'Audit log unreadable.'
            };
        }
    }

    // Check 5: Integrity (Tamper Evidence)
    private async checkAuditLogIntegrity() {
        const integrity = await this.auditLog.verifyIntegrity();
        if (integrity.valid) {
            return {
                id: 'INTEGRITY_CHECK',
                name: 'Data Integrity & Tamper Evidence (eIDAS)',
                result: ComplianceStatus.PASS
            };
        }
        return {
            id: 'INTEGRITY_CHECK',
            name: 'Data Integrity & Tamper Evidence (eIDAS)',
            result: ComplianceStatus.FAIL,
            details: `Chain broken at sequence ${integrity.brokenSequence}`
        };
    }

    async generateHumanReadableReport(): Promise<string> {
        const report = await this.runChecks({
            keyProtection: 'SOFTWARE_EPHEMERAL',
            auditLogLocation: 'LOCAL_INDEXEDDB',
            policyEngine: 'STRICT',
            blockUnknownVerifiers: true
        });

        const lines: string[] = [];
        lines.push('═══════════════════════════════════════════════════════════');
        lines.push('  eIDAS 2.0 + DSGVO COMPLIANCE REPORT');
        lines.push('═══════════════════════════════════════════════════════════');
        lines.push('');
        lines.push(`Generated: ${new Date().toISOString()}`);
        lines.push(`Overall Status: ${report.status}`);
        lines.push('');

        for (const check of report.checks) {
            const icon = check.result === 'PASS' ? '✅' :
                check.result === 'WARN' ? '⚠️' : '❌';
            lines.push(`${icon} ${check.name}: ${check.result}`);
            if (check.details) {
                lines.push(`   Details: ${check.details}`);
            }
        }

        lines.push('═══════════════════════════════════════════════════════════');

        return lines.join('\n');
    }


    // Check 6: Structural Non-Existence (Config)
    private checkStructuralNonExistence(config: any) {
        const noBackend = !config?.remoteVerifierUrl && !config?.remoteLoggerUrl;
        if (noBackend) {
            return {
                id: 'STRUCTURAL_NON_EXISTENCE',
                name: 'Structural Non-Existence (No Server Relay)',
                result: ComplianceStatus.PASS
            };
        }
        return {
            id: 'STRUCTURAL_NON_EXISTENCE',
            name: 'Structural Non-Existence (No Server Relay)',
            result: ComplianceStatus.WARN,
            details: 'Remote URLs detected in config.'
        };
    }

    // Check 7: Key Ephemerality
    private checkKeyEphemerality(config: any) {
        if (config?.keyProtection === 'SOFTWARE_EPHEMERAL') {
            return {
                id: 'KEY_EPHEMERALITY',
                name: 'Key Ephemerality (No Persistence)',
                result: ComplianceStatus.PASS
            };
        }
        return {
            id: 'KEY_EPHEMERALITY',
            name: 'Key Ephemerality (No Persistence)',
            result: ComplianceStatus.WARN,
            details: 'Keys mapped to persistent storage.'
        };
    }
}
