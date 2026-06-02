/**
 * @mitch/wallet-core
 *
 * Core wallet-side modules: sync, budget management, and service facade.
 */

// CRDT ad budget sync (ADR-ADTECH-006)
export type { AdImpressionState } from './sync/crdt-state.js';
export {
    calculateRemaining,
    recordImpression,
    mergeStates,
    needsReset,
    resetCounters,
    createInitialState,
} from './sync/crdt-state.js';

// Storage adapter interface + implementations
export type { SyncStorageAdapter } from './sync/storage-adapter.js';
export {
    InMemorySyncAdapter,
    UnavailableSyncAdapter,
    iCloudAdapter,
    googleDriveAdapter,
} from './sync/storage-adapter.js';

// Phase 2.2: Modular Wallet Services
export * from './ICredentialRepository';
export * from './EncryptedCredentialRepository';
export * from './IPolicyEvaluator';
export * from './MitchPolicyEvaluator';
export * from './IPresentationManager';
export * from './MitchPresentationManager';
export * from './WalletService';
