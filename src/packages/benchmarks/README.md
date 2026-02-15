# Fleetbench Reference Workloads

This package contains the **Performance Baseline** benchmarks for the miTch ecosystem (Phase 6).

## L2 Anchor Stress Test (`l2_stress_test.ts`)

Simulates a "Shredding Storm" of 10,000 concurrent events to validate the efficiency of the Merkle Tree calculation and L2 "Blind Provider" sync.

### Metrics Collected
*   **Ingest Throughput**: Events per second.
*   **Anchor Latency**: Time to calculate the state root (SHA-256 Merkle Chain).
*   **Green Identity**: Estimated CPU energy cost per batch (Joules).

### Usage

```bash
# From root
pnpm install
pnpm build --filter @mitch/audit-log
pnpm --filter @mitch/benchmarks bench:anchor
```

## Workload Definition

*   **Batch Size**: 10,000 events
*   **Algorithm**: SHA-256 (Native WebCrypto via Node adapter)
*   **Constraint**: Anchor Latency < 1000ms
