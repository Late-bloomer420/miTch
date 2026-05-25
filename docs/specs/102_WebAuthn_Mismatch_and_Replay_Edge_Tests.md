# 102 — WebAuthn Mismatch and Replay Edge Tests

Stand: 2026-02-12

Added targeted adversarial tests in `src/tests/core.ts` for strong re-auth evidence handling:

- Signed mode rejects native-context assertion payloads.
- Native mode rejects signed-context assertion payloads.
- Signed mode enforces one-time challenge semantics (replay denied on second use).

Security goal:
Prevent cross-mode assertion confusion and challenge reuse from becoming false-allow paths.
