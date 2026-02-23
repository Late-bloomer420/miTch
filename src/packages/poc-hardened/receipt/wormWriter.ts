import { appendFileSync, mkdirSync, existsSync } from "fs";
import { dirname } from "path";

export interface DecisionReceipt {
  requestId: string;
  decision: "ALLOW" | "DENY";
  decisionCode: string;
  verifiedAt: string;
}

const RECEIPT_PATH = "./data/receipts.log";

export function appendReceipt(receipt: DecisionReceipt): string {
  if (!existsSync(dirname(RECEIPT_PATH))) mkdirSync(dirname(RECEIPT_PATH), { recursive: true });
  const ref = `aqdr:${receipt.verifiedAt}:${receipt.requestId}`;
  appendFileSync(RECEIPT_PATH, JSON.stringify({ ...receipt, receiptRef: ref }) + "\n", "utf8");
  return ref;
}
