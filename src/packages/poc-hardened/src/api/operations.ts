import { appendEvent } from "./eventLog";

export function recordOverride(params: {
  correlationId: string;
  requestId: string;
  previousDecisionCode: string;
  newDecision: "ALLOW" | "DENY";
  reason: string;
}): void {
  appendEvent({
    at: new Date().toISOString(),
    eventType: "decision_override",
    correlationId: params.correlationId,
    requestId: params.requestId,
    decision: params.newDecision,
    decisionCode: params.previousDecisionCode,
    details: {
      reason: params.reason,
    },
  });
}

export function recordAdjudication(params: {
  correlationId: string;
  requestId: string;
  outcome: "legit" | "false_deny" | "false_allow";
}): void {
  appendEvent({
    at: new Date().toISOString(),
    eventType: "adjudication_recorded",
    correlationId: params.correlationId,
    requestId: params.requestId,
    details: {
      outcome: params.outcome,
    },
  });
}
