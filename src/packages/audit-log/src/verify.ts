import { AuditLogExport } from '@mitch/shared-types';
import { sha256, verifyData, canonicalStringify } from '@mitch/shared-crypto';

/**
 * Independent Auditor Tool: Verifies a miTch Audit Report.
 * 
 * Checks:
 * 1. Hash Chain Integrity (prevHash -> currentHash)
 * 2. Entry Content Integrity (Canonical H1 check)
 * 3. Individual Entry Signatures (H2-H4 check)
 * 4. Report-wide Integrity (H5 check - prevents cherry-picking)
 */
export async function verifyAuditReport(
    report: AuditLogExport,
    publicKey: CryptoKey
): Promise<{ valid: boolean; error?: string; brokenIndex?: number }> {

    // 1. Verify Entry-by-Entry Chain
    for (let i = 0; i < report.entries.length; i++) {
        const entry = report.entries[i];
        const prevHash = i > 0 ? report.entries[i - 1].currentHash : '0'.repeat(64);

        // Chain Link Check
        if (entry.previousHash !== prevHash) {
            return { valid: false, error: `Hash chain link broken at index ${i}`, brokenIndex: i };
        }

        // Content integrity (Canonical H1)
        const dataToHash = canonicalStringify({
            id: entry.id,
            timestamp: entry.timestamp,
            action: entry.action,
            subjectId: entry.subjectId,
            previousHash: entry.previousHash,
            metadata: entry.metadata,
            version: entry.version,
            sigAlg: entry.sigAlg,
            kid: entry.kid
        });

        const computedHash = await sha256(dataToHash);
        if (computedHash !== entry.currentHash) {
            return { valid: false, error: `Content hash mismatch at index ${i}`, brokenIndex: i };
        }

        // Signature Check (H2 & H4)
        if (!entry.signature) {
            return { valid: false, error: `Missing signature at index ${i}`, brokenIndex: i };
        }

        const isSignatureValid = await verifyData(dataToHash, entry.signature, publicKey);
        if (!isSignatureValid) {
            return { valid: false, error: `Invalid entry signature at index ${i}`, brokenIndex: i };
        }
    }

    // 2. Verify Report-wide Signature (H5 - Prevents Cherry-Picking)
    const entriesCanonical = canonicalStringify(report.entries.map(e => ({
        id: e.id,
        hash: e.currentHash,
        sig: e.signature
    })));

    const computedReportHash = await sha256(entriesCanonical);
    if (computedReportHash !== report.reportHash) {
        return { valid: false, error: 'Report-level hash mismatch (Potential cherry-picking or reordering detected)' };
    }

    if (!report.signature) {
        return { valid: false, error: 'Report-level signature missing' };
    }

    const isReportSignatureValid = await verifyData(report.reportHash, report.signature, publicKey);
    if (!isReportSignatureValid) {
        return { valid: false, error: 'Report-level signature invalid' };
    }

    return { valid: true };
}
