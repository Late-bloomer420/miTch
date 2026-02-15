# 26 — Repository Hygiene Plan

Stand: 2026-02-11

## Context
Remote history currently includes large generated/dependency content (e.g., `node_modules`, `dist`).
For long-term maintainability and faster CI, repository hygiene should be enforced.

---

## Proposed Actions
1. Extend `.gitignore` to include:
   - `node_modules/`
   - `dist/`
   - build caches
2. Add package scripts for reproducible build from source.
3. Keep generated artifacts out of git by default.
4. Optional: history cleanup phase (only if team approves) to remove heavy artifacts from history.

---

## Safety Note
History rewrite affects collaborators and should only happen with explicit approval.

---

## Minimal `.gitignore` additions
```gitignore
node_modules/
dist/
*.log
```
