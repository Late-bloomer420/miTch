import 'fake-indexeddb/auto';
import { beforeEach } from 'vitest';

// Delete the known LocalAuditLog database before each test to prevent cross-test contamination.
// Avoid indexedDB.databases() — not reliably implemented in fake-indexeddb v6.
beforeEach(() => {
  indexedDB.deleteDatabase('mitch-audit-log');
});
