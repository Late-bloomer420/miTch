export type StatusUnavailableMode = "fail_closed" | "grace_low_risk";

export interface RevocationConfig {
  highRiskPurposes: string[];
  statusUnavailableMode: StatusUnavailableMode;
}

export const revocationConfig: RevocationConfig = {
  highRiskPurposes: (process.env.HIGH_RISK_PURPOSES ?? "age_gate_checkout")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  statusUnavailableMode: (process.env.STATUS_UNAVAILABLE_MODE as StatusUnavailableMode) || "fail_closed",
};

export function shouldFailClosedOnStatusUnavailable(purpose: string): boolean {
  if (revocationConfig.highRiskPurposes.includes(purpose)) return true;
  return revocationConfig.statusUnavailableMode === "fail_closed";
}
