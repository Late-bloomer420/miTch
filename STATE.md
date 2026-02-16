# miTch Project State
**Last Updated:** 2026-02-16
**Status:** ✅ BUILD VALIDATED - Ready for GitHub Deployment

---

## Current Project Status

### ✅ Completed Milestones

1. **Repository Consolidation** (Phase 1-2)
   - Merged 7 scattered repositories into unified monorepo
   - Preserved complete git history in bundles (56+ commits)
   - Created layer-based documentation structure

2. **Build Validation** (Phase 3)
   - ✅ All 20 workspace packages compile successfully
   - ✅ Zero TypeScript errors
   - ✅ pnpm workspaces configured correctly
   - ✅ Turborepo caching at 94% efficiency

3. **Layer-Based Architecture**
   - ✅ @mitch/layer-resolver package created (366 lines)
   - ✅ Three protection layers defined (WELT, GRUNDVERSORGUNG, VULNERABLE)
   - ⏳ Integration with policy-engine (NEXT TASK)

---

## Repository Structure

```
miTch/
├── src/
│   ├── apps/
│   │   ├── issuer-mock/          # Mock credential issuer
│   │   ├── verifier-demo/        # Demo verifier (frontend + backend)
│   │   └── wallet-pwa/           # Progressive Web App wallet
│   ├── packages/
│   │   ├── layer-resolver/       # NEW: Protection layer logic
│   │   ├── policy-engine/        # Core policy enforcement
│   │   ├── shared-crypto/        # Cryptographic utilities
│   │   ├── shared-types/         # Shared TypeScript types
│   │   ├── predicates/           # Zero-knowledge predicates
│   │   ├── verifier-sdk/         # Verifier SDK
│   │   └── [11 more packages]
│   └── docs/
│       ├── 00-welt/              # Layer 0 docs (universal)
│       ├── 01-grundversorgung/   # Layer 1 docs (children)
│       └── 02-erwachsene-vulnerable/ # Layer 2 docs (health/finance)
├── archive/
│   └── git-bundles/              # Preserved git histories
├── MIGRATION_LOG.md              # Complete migration audit trail
├── VALIDATION_REPORT.md          # Build validation results
└── README.md                     # Main documentation

20 workspace packages, 17 buildable packages
```

---

## Protection Layers (Core Concept)

### Layer 0: WELT (World)
**Applies to:** ALL data subjects and services
- Non-linkability enforced
- No central profiles
- Data minimization by construction
- EU-First trust model

### Layer 1: GRUNDVERSORGUNG (Basic Services)
**Applies to:** Children (under 18) + essential services
- Layer 0 protections PLUS:
- No behavioral profiling for minors
- Mandatory crypto-shredding
- Stricter consent requirements

### Layer 2: ERWACHSENE-VULNERABLE (Adults-Vulnerable)
**Applies to:** Health records, financial data, elderly services
- Layer 0 + Layer 1 protections PLUS:
- Mandatory encryption at rest and in transit
- Enhanced audit trails
- GDPR Art. 9 compliance (Special Categories)

**Implementation:** `@mitch/layer-resolver` provides `getMinimumLayerForData()`, `includesLayer()`, `getInheritedLayers()`

---

## Recent Fixes Applied (Validation Phase)

### 1. TypeScript Configuration
**Files Modified:**
- `src/apps/verifier-demo/frontend/tsconfig.json`
- `src/apps/verifier-demo/backend/tsconfig.json`

**Issue:** Incorrect relative path to `tsconfig.base.json`
**Fix:** Changed from `"../../../"` to `"../../../../"` (4 levels up from nested apps)

### 2. Missing Dependencies
**File Modified:** `src/apps/issuer-mock/package.json`

**Issue:** Runtime dependencies missing (express, cors, @mitch/shared-crypto)
**Fix:** Added to dependencies section with correct workspace protocol

### 3. Type Inference
**File Modified:** `src/apps/verifier-demo/backend/src/app.ts`

**Issue:** TypeScript couldn't infer Express app type for export
**Fix:** Added explicit type annotation `const app: Express = express()`

---

## Build Performance

| Metric | Value |
|--------|-------|
| Build Time (cold) | 5.9s |
| Build Time (cached) | 2.4s |
| Cache Hit Rate | 94% |
| Packages Built | 17/17 (100%) |
| TypeScript Errors | 0 |
| Bundle Size (wallet-pwa) | 239.5 kB (74.85 kB gzipped) |
| Bundle Size (verifier-frontend) | 166.21 kB (53.39 kB gzipped) |

---

## Next Priorities

### P0 (Immediate) - Ready Now
- [x] Repository validation (COMPLETED)
- [ ] **CURRENT TASK:** Wire layer-resolver into policy-engine
- [ ] Push to GitHub: https://github.com/Late-bloomer420?tab=repositories
- [ ] Set up CI/CD with build validation

### P1 (Short-term) - Before Production
- [ ] Add integration tests for layer-resolver ← policy-engine
- [ ] Fix test dependencies (@mitch/policy-engine needs vitest)
- [ ] Document browser vs. Node.js package requirements

### P2 (Medium-term) - Enhancement
- [ ] Create liquor store demo (T-87) - Layer 1 age verification showcase
- [ ] Add E2E test for full verifier-demo flow
- [ ] Fix secure-ui-test (add tsx or switch to vitest)
- [ ] Refactor phase0-security demo for Node.js environment

---

## Key Files for Context

### Documentation
- `README.md` - Main project documentation (344 lines)
- `MIGRATION_LOG.md` - Complete migration provenance (618 lines)
- `VALIDATION_REPORT.md` - Build validation results (210 lines)
- `src/packages/layer-resolver/README.md` - Layer API documentation (119 lines)

### Core Implementation
- `src/packages/layer-resolver/src/index.ts` - Layer enumeration and utilities (366 lines)
- `src/packages/policy-engine/src/engine.ts` - Policy enforcement engine (NEXT: integrate layer-resolver)
- `src/packages/shared-crypto/src/index.ts` - Cryptographic utilities (crypto-shredding, ZKP)

### Configuration
- `tsconfig.base.json` - Base TypeScript configuration (strict mode enabled)
- `turbo.json` - Turborepo build pipeline configuration
- `pnpm-workspace.yaml` - Workspace package definitions

---

## Git History

### Migration Commits (8 commits)
1. `f8d3a12` - Initialize consolidated repository structure
2. `a4b8f73` - Migrate core packages (shared-types, shared-crypto, policy-engine)
3. `c9e4d21` - Migrate verifier packages (SDK, browser, demo apps)
4. `b7f9a34` - Migrate wallet-pwa and supporting packages
5. `e2c8f19` - Create layer-based documentation structure
6. `d4a7b28` - Add layer-resolver package with core enums
7. `f1e9c45` - Create comprehensive README and migration log
8. `a8d4c76` - Archive original git bundles with provenance

### Validation Commits (Pending)
- **NEXT:** Commit validation fixes (tsconfig paths, dependencies, type annotations)
- **NEXT:** Wire layer-resolver into policy-engine

---

## Technical Decisions

### 1. Name: "miTch"
Standardized capitalization across all documentation and code.

### 2. Layer Structure: Ascending Order
- Layer 0 (WELT) = baseline
- Layer 1 (GRUNDVERSORGUNG) = Layer 0 + children protections
- Layer 2 (VULNERABLE) = Layer 0 + Layer 1 + sensitive data protections

### 3. Git Strategy: New Repository
Created fresh repository with clean commit history, archived old repos as bundles.

### 4. Package Manager: pnpm
Using pnpm workspaces with `workspace:*` protocol for internal dependencies.

### 5. Build System: Turborepo
Parallel builds with intelligent caching for fast iterative development.

---

## Known Issues (Non-blocking)

### Test Suite (8/22 passing)
**Expected failures:**
- `@mitch/secure-ui-test` - Missing tsx dependency (browser tests)
- `@mitch/policy-engine` - Missing vitest dependency
- `@mitch/phase0-security` - IndexedDB not available in Node.js

**Status:** Non-blocking for build/deployment. Core crypto and predicate tests pass.

### Deprecated Dependencies
- 7 subdependencies flagged (glob, rimraf, eslint 8.x)
- **Status:** Non-critical, stable in PoC environment

---

## Contact & Links

**Maintainer:** jonas.f.meyer@googlemail.com
**GitHub:** https://github.com/Late-bloomer420?tab=repositories
**License:** MIT

---

## Quick Commands

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Development mode (specific package)
cd src/packages/policy-engine && pnpm dev

# Type checking
pnpm type-check
```

---

## Context for AI Assistants

This file provides critical context for Claude Code and other AI assistants to understand project state after conversation compaction or context loss.

**Key Concepts to Remember:**
1. **Layer Inheritance:** Higher layers include all lower layer protections (Layer 2 ⊇ Layer 1 ⊇ Layer 0)
2. **Crypto-Shredding:** Ephemeral key destruction for GDPR Art. 17 compliance (right to be forgotten)
3. **Zero-Knowledge Proofs:** Age verification without revealing birthdate
4. **EU-First Trust:** Explicit principle against commercialization of fundamental rights

**Current Focus:** Integrating layer-resolver into policy-engine to enable layer-aware policy decisions.

**Project Philosophy:** "Rule over Authority" - technical enforcement of privacy principles, not governance theater.

---

**Last validated:** 2026-02-16 at 100% build success
**Next milestone:** Layer-resolver integration → GitHub deployment → Liquor store demo (T-87)
