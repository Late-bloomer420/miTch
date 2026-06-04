import { PolicyEngine, type EvaluationContext } from '@askmi/policy-engine';
import {
  PolicyManifest,
  VerifierRequest,
  PolicyEvaluationResult,
  StoredCredentialMetadata,
  ASKMI_STORAGE_KEYS,
} from '@askmi/shared-types';
import type { IPolicyEvaluator } from './IPolicyEvaluator';

/**
 * Concrete implementation of IPolicyEvaluator using @askmi/policy-engine.
 */
export class AskmiPolicyEvaluator implements IPolicyEvaluator {
  private engine: PolicyEngine;
  private storage: Storage;
  private readonly STORAGE_KEY = ASKMI_STORAGE_KEYS.walletPolicy;

  constructor(engine: PolicyEngine, storage: Storage) {
    this.engine = engine;
    this.storage = storage;
  }

  async evaluate(
    request: VerifierRequest,
    context: EvaluationContext,
    credentials: StoredCredentialMetadata[],
    policy: PolicyManifest
  ): Promise<PolicyEvaluationResult> {
    return this.engine.evaluate(request, context, credentials, policy);
  }

  getPolicy(): PolicyManifest {
    const raw = this.storage.getItem(this.STORAGE_KEY);
    if (!raw) throw new Error('POLICY_NOT_INITIALIZED');
    return JSON.parse(raw) as PolicyManifest;
  }

  savePolicy(policy: PolicyManifest): void {
    this.storage.setItem(this.STORAGE_KEY, JSON.stringify(policy));
  }
}
