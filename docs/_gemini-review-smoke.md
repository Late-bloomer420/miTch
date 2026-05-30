# Gemini review smoke test (throwaway)

This file exists only to trigger the Gemini Dispatch → review workflow on a PR,
to confirm the bot now runs (after the `GEMINI_API_KEY` secret was configured and
the auth-gate from #49). **This PR is not meant to be merged** — it will be closed
and its branch deleted once the review is observed.

A tiny snippet for the reviewer to look at:

```ts
function add(a: number, b: number): number {
  return a + b;
}
```
