# Secure UI Sandbox Tests

This package contains the **SwiftShader-based** integrity tests for the miTch wallet UI (Phase 6).

## Tests

### 1. Context Pinning (`context_pinning.test.ts`)
Verifies that critical security UI elements (e.g. "Shred Now" button) render deterministically without GPU acceleration. This prevents overlay attacks and GPU side-channel leaks.

## Usage

Run from the **repository root**:

```bash
# Install Playwright browsers (if not already installed)
npx playwright install chromium

# Run the test
npx tsx packages/secure-ui-test/src/context_pinning.test.ts
```

## Configuration
See `src/launcher.ts` for the SwiftShader and hardening flags used.
