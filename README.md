# miTch - The Forgetting Layer

**User-Sovereign Identity & Authorization Infrastructure**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

> **"miTch is Trust for everything that is NOT free of User PII"**

miTch is a technical Convenor infrastructure that provides **Compliance-as-a-Service** through automated, cryptographic forgetting (Crypto-Shredding) and privacy-preserving verifications without storing data.

---

## 🎯 Core Philosophy

**miTch works not because it knows everything – but because it structurally cannot know anything.**

### Protection Layers

miTch implements a **layer-based protection model**:

| Layer | Name | Purpose | Examples |
|-------|------|---------|----------|
| **Layer 0** | **WELT** (World) | Universal principles, global rules | Policy manifest, fundamental rights |
| **Layer 1** | **GRUNDVERSORGUNG** (Basic Services) | Children + essential services | Age verification, basic identity |
| **Layer 2** | **ERWACHSENE-VULNERABLE** (Adults-Vulnerable) | Health, elderly, finance | EHDS health records, financial services |

**Principle:** Higher layers inherit protections from lower layers. No commercialization of fundamental rights.

---

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ (LTS recommended)
- pnpm 9.0.0+

### Installation

```bash
# Clone repository
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run wallet PWA
pnpm dev:wallet
```

### Git Integration (recommended once per clone)

```bash
# configure local git defaults + repo hooks
pnpm git:setup

# verify integration status
pnpm git:check
```

This enables local repository hygiene hooks (`.githooks/pre-commit`) and safe defaults for pull/fetch behavior.

### Repository Structure

```
miTch/
├── docs/                           # Documentation (by layer)
│   ├── 00-welt/                   # Layer 0: Universal principles
│   ├── 01-grundversorgung/        # Layer 1: Basic services + kids
│   ├── 02-erwachsene-vulnerable/  # Layer 2: Health, elderly, finance
│   ├── 03-architecture/           # Technical architecture
│   ├── 04-legal/                  # GDPR, compliance, certification
│   └── 05-business/               # Business model, monetization
├── src/
│   ├── apps/                      # Applications
│   │   ├── wallet-pwa/           # Main wallet PWA
│   │   ├── issuer-mock/          # Mock credential issuer
│   │   └── verifier-demo/        # Demo verifier service
│   └── packages/                  # Shared packages
│       ├── policy-engine/        # Core policy evaluation
│       ├── shared-crypto/        # Cryptographic primitives
│       ├── audit-log/            # Immutable audit chain
│       ├── secure-storage/       # Encrypted storage
│       └── [11 more...]
└── archive/                       # Historical preservation
    ├── git-bundles/              # Original repository histories
    └── prototypes/               # Early implementations
```

---

## 🔑 Core Features

### ✅ Crypto-Shredding (Automatic Forgetting)
- Data encrypted with ephemeral keys `K_trans`
- Keys destroyed after transaction completion
- GDPR Art. 17 compliant erasure
- Mathematically irreversible

### ✅ Layer-Aware Policy Engine
- Rule-based (not authority-based) trust
- Protection layer enforcement
- Data minimization by construction
- User sovereignty

### ✅ Zero-Knowledge Proofs
- Age verification without date of birth
- Selective credential disclosure
- Predicate evaluation (e.g., "is_over_18")
- No PII leakage to verifiers

### ✅ Audit-by-Design
- Immutable hash-chain audit log
- Crypto-shredding proof generation
- Local audit (no central tracking)
- Exportable compliance reports

---

## 📚 Documentation

### Start Here
1. **[Project OnePager](docs/00-welt/01_Project_OnePager.md)** - Quick overview
2. **[Principles & Non-Negotiables](docs/00-welt/02_Principles_and_NonNegotiables.md)** - Core values
3. **[Policy Manifest](docs/00-welt/mitch_policy_manifest.md)** - Binding policies
4. **[Master Brief](docs/00-welt/MASTER_BRIEF.md)** - Complete vision

### Key Concepts
- **[Data Flows & PII Boundaries](docs/00-welt/04_Data_Flows_and_PII_Boundaries.md)**
- **[Threat Model](docs/00-welt/05_Threat_Model.md)**
- **[Policy Engine Specification](docs/00-welt/06_Policy_Engine_Spec.md)**

### Development
- **[MVP Execution Plan](docs/03-architecture/mvp/12_MVP_Execution_Plan_6_Weeks.md)**
- **[Architecture Decision Log](docs/03-architecture/mvp/16_MVP_Architecture_Decision_Log.md)**
- **[API Contract](docs/03-architecture/mvp/17_API_Contract_v0.md)**

### Legal & Compliance
- **[GDPR Crypto-Shredding Memo](docs/04-legal/MEMO_GDPR_SHREDDING.md)** ⚠️ Critical
- **[Certification Readiness](docs/04-legal/certification_readiness_mapping.md)**
- **[Digital Rights Charter](docs/00-welt/digital_rights_charter.md)**

---

## 🏗️ Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────┐
│                      miTch Convener                      │
│              (Rules Enforcement Layer)                   │
└─────────────────────────────────────────────────────────┘
                          ↑
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌───────▼──────┐  ┌──────▼──────┐
│   Holder     │  │    Issuer    │  │  Verifier   │
│  (Wallet)    │  │  (Gov/Bank)  │  │   (Shop)    │
│              │  │              │  │             │
│ • Local Keys │  │ • Signs VCs  │  │ • Requests  │
│ • ZK Proofs  │  │ • OID4VCI    │  │ • Receives  │
│ • Crypto-    │  │              │  │   Proofs    │
│   Shredding  │  │              │  │   (no PII)  │
└──────────────┘  └──────────────┘  └─────────────┘
```

### Edge-First Architecture
- **Local Decisions:** All data release decisions on user device
- **Ephemerality:** Data exists only transactionally, default is "deleted"
- **Blind Provider:** miTch sees metadata for audit, never PII

---

## 🧪 Use Cases

### 1. Age Verification (Beachhead)
**Problem:** EU GDPR requires child protection, but age checks lead to mass data collection

**miTch Solution:**
1. User wallet computes: `(today - birthDate) >= 18`
2. Sends only: `{"isOver18": true}` + cryptographic proof
3. Shop receives guarantee without storing date of birth
4. Session key destroyed (Crypto-Shredding)

**Benefits:**
- No PII storage = no data breach risk
- Automatic GDPR compliance
- Faster onboarding (single-click verify)

### 2. Health Records (EHDS Layer 2)
- Emergency access to critical health data
- Selective disclosure (e.g., allergies only)
- Layer 2 protection: no commercialization

### 3. Professional Credentials
- Employment verification without full CV
- License validation without tracking
- Zero-knowledge credential proofs

---

## 🛠️ Development

### Monorepo Structure

This is a **pnpm workspace monorepo** using Turborepo.

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Development mode (wallet)
pnpm dev:wallet

# Lint & format
pnpm lint
pnpm format

# Clean build artifacts
pnpm clean
```

### Key Packages

| Package | Purpose |
|---------|---------|
| `@mitch/policy-engine` | Core policy evaluation logic |
| `@mitch/shared-crypto` | Crypto-shredding, ephemeral keys, ZKPs |
| `@mitch/audit-log` | Immutable audit chain implementation |
| `@mitch/secure-storage` | Encrypted credential storage |
| `@mitch/predicates` | Zero-knowledge predicate evaluation |
| `@mitch/oid4vci` | OpenID for Verifiable Credential Issuance |
| `@mitch/verifier-sdk` | Server-side verifier library |
| `@mitch/verifier-browser` | Client-side verifier (zero-backend) |

---

## 📊 Project Status

**Current Phase:** Phase 5 - SME Pilot Readiness

### Milestones
- [x] **Phase 1-4:** Core implementation (policy-engine, crypto-shredding, audit)
- [x] **Phase 5 (Active):** 15-minute integration for small businesses
- [ ] **Phase 6:** Production hardening
- [ ] **Phase 7:** Certification (GDPR, eIDAS)
- [ ] **Phase 8:** Public launch

### Active Tasks
- [ ] T-85: Browser Verifier SDK (`@mitch/verifier-browser`)
- [ ] T-86: Ephemeral Key Generation (client-side)
- [ ] T-87: Liquor Store Demo Page
- [ ] T-88: Wallet Ephemeral Support

See [BACKLOG](docs/00-welt/07_Backlog_and_Roadmap.md) for detailed roadmap.

---

## ⚖️ Legal & Governance

### Non-Negotiable Principles
1. **Rule over Authority** - Trust from rules, not central power
2. **Data Minimization by Construction** - Built-in, not bolted-on
3. **User Sovereignty** - User controls all data releases
4. **Non-Linkability** - No cross-service tracking possible
5. **EU-First Trust** - GDPR/eIDAS compliant by design

### Absolute Prohibitions (Never Events)
- ❌ Central user profiles
- ❌ Cross-service tracking
- ❌ Data commercialization
- ❌ **Commercialization of fundamental rights** (Teilhabe ohne Datenzwang)

See [Policy Manifest](docs/00-welt/mitch_policy_manifest.md) for binding policies.

---

## 🤝 Contributing

We welcome contributions that align with miTch's core principles!

### Before Contributing
1. Read [Principles & Non-Negotiables](docs/00-welt/02_Principles_and_NonNegotiables.md)
2. Review [Policy Manifest](docs/00-welt/mitch_policy_manifest.md)
3. Check [open issues](https://github.com/Late-bloomer420/miTch/issues)

### Development Guidelines
- All code must pass `pnpm lint` and `pnpm test`
- No central data storage (violates principles)
- Document layer implications (Layer 0/1/2)
- Add tests for policy enforcement
- Follow existing commit conventions

---

## 📜 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

### Key Points
- ✅ Open source (MIT)
- ✅ Free for commercial use
- ✅ No warranty (use at own risk)
- ⚠️ Policy Manifest is protected intellectual property (see governance)

---

## 🔗 Links

- **GitHub:** [github.com/Late-bloomer420/miTch](https://github.com/Late-bloomer420/miTch)
- **Documentation:** [docs/00-welt/00_README.md](docs/00-welt/00_README.md)
- **Issues:** [GitHub Issues](https://github.com/Late-bloomer420/miTch/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Late-bloomer420/miTch/discussions)

---

## 📞 Contact

- **Maintainer:** Late-bloomer420
- **Email:** jonas.f.meyer@googlemail.com
- **GitHub:** [@Late-bloomer420](https://github.com/Late-bloomer420)

---

## 🌟 Acknowledgments

**miTch** builds on the principles of:
- **SSI (Self-Sovereign Identity)** movement
- **Zero-Knowledge Cryptography** research
- **Privacy by Design** methodology
- **EU GDPR** regulatory framework
- **eIDAS** digital identity standards

---

**Remember:** *miTch works not because it knows everything – but because it structurally cannot know anything.*

🔐 **Trust through Rules, Not Authority**

---

*Repository consolidated: 2026-02-15*
*Migration from 7 locations to unified layer-based structure*
*All original git histories preserved in `archive/git-bundles/`*
