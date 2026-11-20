import { describe, expect, it } from 'vitest';
import { AuditLog } from '../src/index';

describe('development anchor fallback', () => {
    it('labels the returned and exported receipt as synthetic', async () => {
        const log = new AuditLog('synthetic-wallet');
        await log.append('KEY_CREATED', 'synthetic-key');

        const receipt = await log.syncToL2();
        const report = await log.exportReport();

        expect(receipt.status).toBe('mocked');
        expect(receipt.network).toBe('mock');
        expect(report.anchors).toEqual([receipt]);
        expect(report.anchors?.[0].status).toBe('mocked');
        expect(report.anchors?.[0].network).toBe('mock');
    });
});
