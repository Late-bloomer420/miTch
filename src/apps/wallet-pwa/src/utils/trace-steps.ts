import type { DataFlowTransaction } from '@askmi/data-flow';

export interface TraceStepValues {
  requested: string;
  allowed: string;
  sent: string;
}

const count = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** Shown for step 3 when a presentation was prepared but no delivery was logged. */
export const NO_DELIVERY_RECORDED = 'No delivery recorded';

/**
 * Short values for the three Disclosure Trace steps, taken from the latest
 * data-flow transaction so each step shows what its label says.
 *
 * "Sent" needs a VP_SENT event. VP_GENERATED is logged when the presentation is
 * prepared, before key resolution, encryption and transmission, so on its own it
 * does not show that anything left the device.
 */
export function describeTraceSteps(txn: DataFlowTransaction | undefined): TraceStepValues {
  if (!txn) return { requested: 'Waiting', allowed: 'Idle', sent: 'Nothing yet' };

  const withheld = txn.claimsWithheld ?? [];
  const requested = txn.claimsRequested ?? [
    ...new Set([...txn.provenClaims, ...txn.claimsShared, ...withheld]),
  ];

  let sent: string;
  if (txn.verdict === 'DENY') {
    sent = 'Nothing sent';
  } else if (!txn.events.some((event) => event.action === 'VP_SENT')) {
    sent = NO_DELIVERY_RECORDED;
  } else {
    sent = `${count(txn.provenClaims.length, 'proof')} · ${txn.claimsShared.length} raw`;
    if (withheld.length > 0) sent += ` · ${withheld.length} withheld`;
  }

  return {
    requested: count(requested.length, 'item'),
    allowed: txn.verdict ?? 'Not logged',
    sent,
  };
}
