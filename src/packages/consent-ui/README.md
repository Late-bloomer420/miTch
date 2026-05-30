# @mitch/consent-ui

Embeddable, framework-agnostic **consent surface** for verifiers.

Renders the disclosure boundary from the marketing brief — _requested · allowed · withheld_ — as a custom element any verifier can drop into any page (or host as a static file on any computer). Wired to the real `@mitch/policy-engine` types: maps a `DisclosureRequest` + `Decision` into the on-screen surface and produces a hash-linked `ConsentReceipt` compatible with `DecisionCapsule` conventions.

## Properties

- **Zero runtime dependencies.** Vanilla TS, Shadow DOM, no React/Vue/etc.
- **Fail-closed.** Raw claims default to *withheld*; only explicit per-item opt-in flips them to *allowed*. Policy-denied items are non-toggleable.
- **No injection surface.** All text goes through `textContent`. No `innerHTML`, no `eval`, no inline `on*=` handlers, no remote resources.
- **No persistence, no network** by default. The host decides where the result goes.
- **Modular.** Theme, i18n, and policy-adapter are independent modules — patch or replace any one.
- **Receipt is minimization-safe.** Verifier id is hashed (`sha256:...`), no raw claim values are stored, request hash binds the receipt to the request.

## Usage

```ts
import { defineConsentElement, fromPolicyDecision } from '@mitch/consent-ui';
import type { DisclosureRequest, Decision } from '@mitch/policy-engine';

defineConsentElement(); // registers <mitch-consent>

const request: DisclosureRequest = /* from your protocol layer */;
const decision: Decision = /* from policyEngine.evaluate(request) */;

const consentRequest = fromPolicyDecision({
    request,
    decision,
    verifierDisplayName: "Joe's Liquor Store",
});

const el = document.querySelector('mitch-consent')!;
(el as any).request = consentRequest;

el.addEventListener('mitch-consent', (e) => {
    const { result, receipt } = (e as CustomEvent).detail;
    // result.verdict: 'CONSENTED' | 'WITHHELD'
    // receipt.verifierRef, receipt.requestHash — hash-linked, no raw values
});

el.addEventListener('mitch-consent-cancel', (e) => {
    const { result } = (e as CustomEvent).detail; // verdict: 'CANCELLED'
});
```

## Events

| Event | Detail |
|---|---|
| `mitch-consent` | `{ result: ConsentResult, receipt: ConsentReceipt }` |
| `mitch-consent-cancel` | `{ result: ConsentResult }` (verdict: `CANCELLED`) |

Both bubble and cross shadow boundaries (`composed: true`).

## Attributes

| Attribute | Meaning |
|---|---|
| `request` | JSON-serialized `ConsentRequest`. Prefer the `.request` property for non-trivial inputs. |
| `lang` | `"en"` (default) or `"de"`. |

Property setters: `request`, `theme`, `strings`.

## Demo

After building the package, open `demo/index.html` from any static server:

```bash
pnpm --filter @mitch/consent-ui build
# then serve the package directory and open /demo/index.html
```

## Tests

```bash
pnpm --filter @mitch/consent-ui test
```

Runs Vitest under jsdom: render safety, fail-closed defaults, toggle behavior, event payloads, malformed-request handling, XSS-resistance of text rendering, German strings.
