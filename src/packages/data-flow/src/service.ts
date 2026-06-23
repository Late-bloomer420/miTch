import type { AuditLogEntry, AuditEventType, IdentityFirewallMetadata } from '@askmi/shared-types';
import { sensitivityFromLayer, type Sensitivity } from '@askmi/layer-resolver';
import type { DataFlowTransaction, DataFlowEvent } from './types';
import { eventLabel } from './labels';

function extractVerifierLabel(did: string | null): string {
  if (!did) return 'Unbekannter Verifier';
  // did:askmi:verifier-liquor-store → Liquor Store
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

      // G-140 PR2: the disclosure decision (POLICY_EVALUATED w/ requested_claims) is
      // logged on EVERY verdict — including DENY, which never produces a VP_GENERATED.
      const disclosureEvent = group.find(
        e => e.action === 'POLICY_EVALUATED' && (e.metadata?.requested_claims as unknown) !== undefined
      );
      const verdict = disclosureEvent?.metadata?.verdict as DataFlowTransaction['verdict'];

      // G-140 surfacing: project the per-claim protection layers (logged on the
      // disclosure event) onto a neutral sensitivity view. No re-resolution here —
      // we read exactly what the engine classified at decision time.
      let claimSensitivity: Record<string, Sensitivity> | undefined;
      const rawLayers = disclosureEvent?.metadata?.requested_claim_layers as
        | Record<string, number | null>
        | undefined;
      if (rawLayers) {
        claimSensitivity = {};
        for (const [claim, layer] of Object.entries(rawLayers)) {
          claimSensitivity[claim] = sensitivityFromLayer(layer);
        }
      }

      // G-140 PR3/PR4: ISO 18013-5 proximity (mdoc) emits VP_SENT rather than
      // VP_GENERATED. PR4 adds POLICY_EVALUATED; keep VP_SENT as the proximity
      // claim source while letting the disclosure event supply verdict/raw request.
      const proximityEvent = group.find(
        e => e.action === 'VP_SENT' && e.metadata?.context === 'PROXIMITY_PRESENTATION'
      );

      const claimsShared =
        (vpEvent?.metadata?.claims_shared as string[] | undefined) ??
        (proximityEvent?.metadata?.claims_shared as string[] | undefined) ??
        [];
      // Prefer the verifier's RAW requested set from the disclosure event so over-asking
      // is measured honestly (gap A); fall back to the VP's own view, then to the proximity
      // event for offline mdoc presentations.
      const claimsRequested =
        (disclosureEvent?.metadata?.requested_claims as string[] | undefined) ??
        (vpEvent?.metadata?.claims_requested as string[] | undefined) ??
        (proximityEvent?.metadata?.claims_requested as string[] | undefined) ??
        null;
      let claimsWithheld: string[] | null = null;
      if (claimsRequested !== null) {
        const sharedOrProvenSet = new Set([
          ...claimsShared,
          ...((vpEvent?.metadata?.proven_claims as string[] | undefined) ?? []),
        ]);
        claimsWithheld = claimsRequested.filter(c => !sharedOrProvenSet.has(c));
      }
      const provenClaims = (vpEvent?.metadata?.proven_claims as string[]) ?? [];
      const credentialTypes = (vpEvent?.metadata?.credential_types as string[]) ?? [];
      const usedZKP = (vpEvent?.metadata?.used_zkp as boolean) ?? false;
      const singleUseCredential = (vpEvent?.metadata?.single_use_credential as boolean) ?? false;
      // DENY transactions have no vpEvent — fall back to the disclosure event's verifier,
      // then to the proximity event for offline mdoc presentations.
      const verifierId =
        (vpEvent?.metadata?.verifier_did as string) ??
        (disclosureEvent?.metadata?.verifier_did as string) ??
        (proximityEvent?.metadata?.verifier_did as string) ??
        null;
      const identityAccesses = group
        .filter(e => e.action === 'IDENTITY_ACCESS_DETECTED')
        .map(e => e.metadata)
        .filter((metadata): metadata is Record<string, unknown> => !!metadata)
        .map(metadata => metadata as unknown as IdentityFirewallMetadata)
        .map(({ decision_id: _decisionId, ...access }) => access);

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
          action: e.action,
          label,
          category,
          metadata: e.metadata,
        };
      });

      transactions.push({
        transactionId: decisionId,
        startedAt: group[0].timestamp,
        completedAt: group[group.length - 1].timestamp,
        verifierId,
        verifierLabel: extractVerifierLabel(verifierId),
        verdict,
        claimSensitivity,
        claimsShared,
        claimsRequested,
        claimsWithheld,
        provenClaims,
        credentialTypes,
        usedZKP,
        singleUseCredential,
        identityAccesses,
        identityAccessCount: identityAccesses.length,
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
