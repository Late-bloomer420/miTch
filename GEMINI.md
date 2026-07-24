# miTch Project Instructions

## Architecture & Principles
- **Fail-closed:** Ambiguous policy evaluations MUST result in `DENY`.
- **Zero-Trust:** All components operate under zero-trust assumptions.
- **Privacy-First:** GDPR Art. 25 + eIDAS 2.0 compliance is a priority.

## Workflow
- **Monorepo:** Use `pnpm` for all package management and task execution.
- **Task Runner:** Use `turbo` for builds, tests, and linting.
- **Commits:** Follow Conventional Commits (`feat:`, `fix:`, etc.).

## Tech Stack
- **Language:** TypeScript
- **Test Framework:** Vitest
- **Package Manager:** pnpm
- **Environment:** Node.js 22

## Key Files
- `CLAUDE.md`: General CLI guidance and commands.
- `SPRINT_PLAN.md`: Current development goals.
- `REFACTORING_ROADMAP.md`: Long-term technical debt and architectural goals.
