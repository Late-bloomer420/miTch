import type { AuditEventType } from '@mitch/shared-types';
import type { DataFlowEvent } from './types';

const LABEL_MAP: Record<AuditEventType, { label: string; category: DataFlowEvent['category'] }> = {
  KEY_CREATED: { label: 'Sitzungsschlüssel erzeugt', category: 'key' },
  KEY_USED: { label: 'Credential entschlüsselt', category: 'credential' },
  KEY_DESTROYED: { label: 'Schlüssel vernichtet', category: 'key' },
  VP_GENERATED: { label: 'Präsentation erstellt', category: 'presentation' },
  VP_SENT: { label: 'Daten an Verifier gesendet', category: 'presentation' },
  POLICY_EVALUATED: { label: 'Policy ausgewertet', category: 'policy' },
  POLICY_BLOCKED: { label: 'Anfrage blockiert', category: 'policy' },
  USER_CONSENT_GRANTED: { label: 'Nutzer hat zugestimmt', category: 'consent' },
  USER_CONSENT_DENIED: { label: 'Nutzer hat abgelehnt', category: 'consent' },
  VC_IMPORTED: { label: 'Credential empfangen', category: 'credential' },
  VC_DELETED: { label: 'Credential gelöscht', category: 'credential' },
};

export function eventLabel(
  action: AuditEventType,
  _metadata?: Record<string, unknown>
): { label: string; category: DataFlowEvent['category'] } {
  return LABEL_MAP[action] ?? { label: action, category: 'policy' };
}
