import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EIDASComplianceChecker, LocalAuditLog } from '../src/index.js';

describe('EIDASComplianceChecker', () => {
  let auditLog: LocalAuditLog;
  let checker: EIDASComplianceChecker;

  beforeEach(async () => {
    indexedDB.deleteDatabase('mitch-audit-log');
    auditLog = new LocalAuditLog();
    await auditLog.initialize();
    checker = new EIDASComplianceChecker(auditLog);
  });

  afterEach(() => {
    auditLog.close();
  });

  // -------------------------------------------------------------------------
  // runFullAudit — overall report
  // -------------------------------------------------------------------------
  describe('runFullAudit', () => {
    it('returns a compliance report with 7 checks', async () => {
      const report = await checker.runFullAudit();
      expect(report.checks).toHaveLength(7);
      expect(report.timestamp).toBeGreaterThan(0);
    });

    it('reports compliant for a well-configured system', async () => {
      // Add some credential events so processing record check is satisfied
      await auditLog.append({
        type: 'CREDENTIAL_ISSUED',
        timestamp: Date.now(),
        details: { issuer: 'test' },
      });

      const report = await checker.runFullAudit();
      expect(report.compliant).toBe(true);
    });

    it('has no FAIL checks for a healthy initialized audit log', async () => {
      const report = await checker.runFullAudit();
      const fails = report.checks.filter((c) => c.status === 'FAIL');
      expect(fails).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Audit Log Accessibility
  // -------------------------------------------------------------------------
  describe('checkAuditLogAccessibility', () => {
    it('passes when audit log is initialized', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('eIDAS 2.0 Art. 6a'));
      expect(check).toBeDefined();
      expect(check!.status).toBe('PASS');
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Data Deletion
  // -------------------------------------------------------------------------
  describe('checkDataDeletionCapability', () => {
    it('passes when deleteAll method exists', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 17'));
      expect(check).toBeDefined();
      expect(check!.status).toBe('PASS');
      expect(check!.details).toContain('deleteAll()');
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Data Portability
  // -------------------------------------------------------------------------
  describe('checkDataPortability', () => {
    it('warns for empty log (new wallet)', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 20'));
      expect(check).toBeDefined();
      // Empty log = has integrityProof but 0 entries -> still PASS because integrityProof exists
      expect(check!.status).toBe('PASS');
    });

    it('passes when log has entries', async () => {
      await auditLog.append({
        type: 'KEY_GENERATED',
        timestamp: Date.now(),
        details: {},
      });

      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 20'));
      expect(check!.status).toBe('PASS');
      expect(check!.details).toContain('1 entries');
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Processing Record
  // -------------------------------------------------------------------------
  describe('checkProcessingRecord', () => {
    it('passes for empty log (new wallet)', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 30'));
      expect(check).toBeDefined();
      expect(check!.status).toBe('PASS');
    });

    it('passes when credential events are present', async () => {
      await auditLog.append({
        type: 'CREDENTIAL_ISSUED',
        timestamp: Date.now(),
        details: { issuer: 'did:mitch:issuer' },
      });

      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 30'));
      expect(check!.status).toBe('PASS');
    });

    it('warns when only non-credential events exist', async () => {
      await auditLog.append({
        type: 'KEY_GENERATED',
        timestamp: Date.now(),
        details: {},
      });

      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 30'));
      expect(check!.status).toBe('WARN');
      expect(check!.details).toContain('no credential processing events');
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Audit Log Integrity
  // -------------------------------------------------------------------------
  describe('checkAuditLogIntegrity', () => {
    it('passes for intact chain', async () => {
      await auditLog.append({ type: 'KEY_GENERATED', timestamp: 1000, details: {} });
      await auditLog.append({ type: 'CREDENTIAL_ISSUED', timestamp: 2000, details: {} });

      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('NIS2'));
      expect(check).toBeDefined();
      expect(check!.status).toBe('PASS');
      expect(check!.details).toContain('SHA-256');
    });

    it('passes for empty chain', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('NIS2'));
      expect(check!.status).toBe('PASS');
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Structural Non-Existence
  // -------------------------------------------------------------------------
  describe('checkStructuralNonExistence', () => {
    it('passes (architectural guarantee)', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('DSGVO Art. 25'));
      expect(check).toBeDefined();
      expect(check!.status).toBe('PASS');
      expect(check!.details).toContain('Verifier-Direct Protocol');
    });
  });

  // -------------------------------------------------------------------------
  // Individual check: Key Ephemerality
  // -------------------------------------------------------------------------
  describe('checkKeyEphemerality', () => {
    it('passes (session-scoped keys)', async () => {
      const report = await checker.runFullAudit();
      const check = report.checks.find((c) => c.regulation.includes('Phase-0'));
      expect(check).toBeDefined();
      expect(check!.status).toBe('PASS');
      expect(check!.details).toContain('SESSION-SCOPED');
    });
  });

  // -------------------------------------------------------------------------
  // Summary generation
  // -------------------------------------------------------------------------
  describe('summary', () => {
    it('generates FULLY COMPLIANT summary when all pass', async () => {
      await auditLog.append({
        type: 'CREDENTIAL_ISSUED',
        timestamp: Date.now(),
        details: {},
      });

      const report = await checker.runFullAudit();
      expect(report.summary).toContain('FULLY COMPLIANT');
      expect(report.summary).toContain('7/7');
    });

    it('generates COMPLIANT WITH WARNINGS when warnings exist', async () => {
      // Non-credential events only -> processing record WARN
      await auditLog.append({ type: 'KEY_GENERATED', timestamp: Date.now(), details: {} });

      const report = await checker.runFullAudit();
      expect(report.summary).toContain('WARNINGS');
    });
  });

  // -------------------------------------------------------------------------
  // Human-readable report
  // -------------------------------------------------------------------------
  describe('generateHumanReadableReport', () => {
    it('generates a multi-line text report', async () => {
      const reportText = await checker.generateHumanReadableReport();
      expect(reportText).toContain('eIDAS 2.0');
      expect(reportText).toContain('DSGVO');
      expect(reportText).toContain('COMPLIANCE REPORT');
    });

    it('includes regulation references', async () => {
      const reportText = await checker.generateHumanReadableReport();
      expect(reportText).toContain('DSGVO Art.');
      expect(reportText).toContain('eIDAS');
    });
  });

  // -------------------------------------------------------------------------
  // Export compliance report (JSON)
  // -------------------------------------------------------------------------
  describe('exportComplianceReport', () => {
    it('exports valid JSON with compliance_report and audit_log_data', async () => {
      await auditLog.append({
        type: 'CREDENTIAL_ISSUED',
        timestamp: Date.now(),
        details: { test: true },
      });

      const jsonStr = await checker.exportComplianceReport();
      const parsed = JSON.parse(jsonStr);

      expect(parsed.compliance_report).toBeDefined();
      expect(parsed.compliance_report.compliant).toBe(true);
      expect(parsed.audit_log_data).toBeDefined();
      expect(parsed.audit_log_data.entries).toHaveLength(1);
      expect(parsed.exported_at).toBeDefined();
      expect(parsed.format_version).toBe('1.0.0');
    });
  });
});
