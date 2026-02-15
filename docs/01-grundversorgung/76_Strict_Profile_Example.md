# 76 — Strict Profile Example

Stand: 2026-02-11

Added `.env.strict.example` for production-like security checks.

## Highlights
- Enforces jurisdiction matching
- Enables strong re-auth mode
- Uses tighter status-source limits (timeout/size/cache)
- Tightens KPI thresholds and fails on warnings

## Usage
1. Copy `.env.strict.example` to `.env`
2. Replace placeholder values (token, URLs, assertions)
3. Run:
   - `npm test`
   - `npm run kpi:check`
