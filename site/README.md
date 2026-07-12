# `site/` — GitHub Pages source

`index.html` is the self-contained landing page published by
`.github/workflows/pages.yml` to GitHub Pages.

## Provenance / why this exists

This file was **extracted from `src/packages/poc-hardened/src/poc-web/standalone.html`**
on 2026-07-07 to decouple the Pages deploy from the `@askmi/poc-hardened`
package. The PoC package's *logic* is dead (nothing imports `@askmi/poc-hardened`;
its proof-fatigue / rate-limiter behaviour was re-implemented in
`@askmi/policy-engine`), but the Pages workflow still reached into it for this
one HTML file — which blocked removing the package.

With this copy as the canonical Pages source, `poc-hardened` has no remaining
consumers. The original file is intentionally left in place for now (no delete
yet); once this separation is confirmed on `master`, the package can be removed
in a dedicated, reviewed step.

The page is fully self-contained (no relative asset references), so this single
file is the entire deploy artifact.
