import type { AuditLogEntry, AuditEventType } from '@mitch/shared-types';
import type { DataFlowTransaction, DataFlowEvent } from './types';
import { eventLabel } from './labels';

function extractVerifierLabel(did: string | null): string {
  if (!did) return 'Unbekannter Verifier';
  // did:mitch:verifier-liquor-store → Liquor Store
  const parts = did.split(':');
  const last = parts[parts.length - 1];
  return last
    .replace(/^verifier-/, '')
    .split('-')
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

export class DataFlowService {
  buildTransactions(entries: AuditLogEntry[]): DataFlowTransaction[] {
    // Group by decision_id
    const groups = new Map<string, AuditLogEntry[]>();

    for (const entry of entries) {
      const decisionId = entry.metadata?.decision_id as string | undefined;
      if (!decisionId) continue;

      let group = groups.get(decisionId);
      if (!group) {
        group = [];
        groups.set(decisionId, group);
      }
      group.push(entry);
    }

    const transactions: DataFlowTransaction[] = [];

    for (const [decisionId, group] of groups) {
      // Sort by timestamp ascending
      group.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

      // Find VP_GENERATED event for claim data
      const vpEvent = group.find(e => e.action === 'VP_GENERATED');

      const claimsShared = (vpEvent?.metadata?.claims_shared as string[]) ?? [];
      const provenClaims = (vpEvent?.metadata?.proven_claims as string[]) ?? [];
      const credentialTypes = (vpEvent?.metadata?.credential_types as string[]) ?? [];
      const usedZKP = (vpEvent?.metadata?.used_zkp as boolean) ?? false;
      const verifierId = (vpEvent?.metadata?.verifier_did as string) ?? null;

      // Lifecycle
      const keyCreated = group.filter(e => e.action === 'KEY_CREATED');
      const keyDestroyed = group.filter(e => e.action === 'KEY_DESTROYED');
      const keysCreated = keyCreated.length;
      const keysDestroyed = keyDestroyed.length;
      const fullyShredded = keysCreated > 0 && keysCreated === keysDestroyed;

      let shreddingLatencyMs: number | null = null;
      if (keyCreated.length > 0 && keyDestroyed.length > 0) {
        const firstCreated = new Date(keyCreated[0].timestamp).getTime();
        const lastDestroyed = new Date(keyDestroyed[keyDestroyed.length - 1].timestamp).getTime();
        shreddingLatencyMs = lastDestroyed - firstCreated;
      }

      // Build events
      const events: DataFlowEvent[] = group.map(e => {
        const { label, category } = eventLabel(e.action as AuditEventType, e.metadata as Record<string, unknown> | undefined);
        return {
          auditEntryId: e.id,
          timestamp: e.timestamp,
          label,
          category,
        };
      });

      transactions.push({
        transactionId: decisionId,
        startedAt: group[0].timestamp,
        completedAt: group[group.length - 1].timestamp,
        verifierId,
        verifierLabel: extractVerifierLabel(verifierId),
        claimsShared,
        provenClaims,
        credentialTypes,
        usedZKP,
        lifecycle: {
          keysCreated,
          keysDestroyed,
          fullyShredded,
          shreddingLatencyMs,
        },
        events,
      });
    }

    // Sort newest first
    transactions.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());

    return transactions;
  }
}
