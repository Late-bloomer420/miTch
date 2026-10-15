import { describe, it } from 'vitest';
import { DataFlowService } from '../service';
import type { AuditLogEntry } from '@askmi/shared-types';

function makeEntry(overrides: Partial<AuditLogEntry> & Pick<AuditLogEntry, 'action'>): AuditLogEntry {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    previousHash: '0'.repeat(64),
    currentHash: 'a'.repeat(64),
    ...overrides,
  };
}

describe('DataFlowService Benchmark', () => {
  it('should measure the performance of buildTransactions', () => {
    const service = new DataFlowService();
    const numTransactions = 5000;
    const entriesPerTransaction = 5;
    const entries: AuditLogEntry[] = [];

    // Generate test data
    const baseDate = Date.now();
    for (let i = 0; i < numTransactions; i++) {
      const decisionId = `decision-${i}`;
      // Give each transaction a different timestamp
      const txTimestampMs = baseDate - i * 10000;

      for (let j = 0; j < entriesPerTransaction; j++) {
        // Events within a transaction have slightly different timestamps
        const eventTimestampMs = txTimestampMs + j * 100;
        entries.push(
          makeEntry({
            action: j === 0 ? 'POLICY_EVALUATED' : 'VP_GENERATED',
            timestamp: new Date(eventTimestampMs).toISOString(),
            metadata: {
              decision_id: decisionId,
              requested_claims: ['age'],
            },
          })
        );
      }
    }

    // Shuffle entries slightly to make the sort work
    for (let i = entries.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [entries[i], entries[j]] = [entries[j], entries[i]];
    }

    const start = performance.now();
    const result = service.buildTransactions(entries);
    const end = performance.now();

    console.log(`[Benchmark] buildTransactions with ${numTransactions} transactions (${entries.length} entries) took ${end - start} ms`);
  });
});
