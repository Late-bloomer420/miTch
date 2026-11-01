# Pre-login "What websites can already see" panel: design note

**Status:** Proposed (2026-10-27). This is a design, not an implementation; see `docs/DOCS_CANON.md`.
**Tracking:** #220
**Reference design (not a dependency):** [miTch-Transparency-Layer](https://github.com/Late-bloomer420/miTch-Transparency-Layer) v0.3, `popup.js` `renderReport()`.

## 1. Intent

Before someone creates or unlocks their wallet, show them what any website can
already read about their browser and device, without asking. In a few seconds
it makes concrete the problem AskMI exists to solve: every site learns a lot
before you have shared anything. It also works as the opening act of the demo.

Success: a first-time visitor reads the panel and understands, without jargon,
(a) what was just read, (b) what a site _could_ additionally get, and (c) what
nobody can see from the browser at all. The panel must be trustworthy enough
that a privacy-literate reviewer finds nothing overclaimed.

## 2. Guardrails (agreed in #220, restated as testable invariants)

| #   | Guardrail                   | Invariant the implementation must satisfy                                                                                                                                                                                                  |
| --- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| G1  | On-device only              | Values are computed in the browser, held only in component state, and dropped on hide or unmount. They are never written to localStorage, IndexedDB, the audit log or any service. The only persisted value is a boolean "dismissed" flag. |
| G2  | Never an input to decisions | No score, no aggregate, no hash or combined identifier, no "suspicious device". The collector module imports nothing from `services/` and nothing imports it except the panel component.                                                   |
| G3  | No server lookups           | No `fetch`, XHR, `sendBeacon`, WebSocket, WebRTC or image beacon in the collector or panel. No IP or geolocation lookup. The IP is mentioned only as a plain-language fact under _Potential_.                                              |
| G4  | Every item labelled         | Each item carries a layer (`observed` / `potential` / `unknown`) and a "what this reveals" sentence. This is enforced by the TypeScript type, not by convention.                                                                           |
| G5  | Dismissible                 | Collapsed by default. "Hide" persists a dismissed flag, and it can be reopened later from Settings. It is never forced on every login.                                                                                                     |

`docs/DOCS_CANON.md` keeps _fingerprinting prevention_ as a product goal. G2 and the
"deliberately not computed" list in §3 are how this panel stays an
explanation of fingerprinting rather than an instance of it.

## 3. The three layers: stricter than the reference

The reference extension puts values it actually read (screen, language,
timezone, user agent) under "potential access", next to the IP address, which
only servers see. The wallet uses a stricter split, so each label stays literally
true:

### Observed: read on this screen, just now, with no prompt

Shown with the actual value, because seeing your own value is the point.
Missing APIs show "not exposed by this browser".

| Item                | Source                                                                                  | What it reveals (draft copy)                                                                     |
| ------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Browser and OS      | `navigator.userAgent`; low-entropy `navigator.userAgentData` (brands, platform, mobile) | Your browser, its version and your operating system                                              |
| Languages           | `navigator.languages`                                                                   | Which languages you read, often your country                                                     |
| Time zone           | `Intl.DateTimeFormat().resolvedOptions().timeZone`                                      | Roughly where you are                                                                            |
| Screen              | `screen.width/height`, `availWidth/Height`, `devicePixelRatio`, `colorDepth`            | Device class; combined with others it narrows you down                                           |
| Hardware            | `navigator.hardwareConcurrency`, `navigator.deviceMemory` (Chromium)                    | Rough device price class                                                                         |
| Touch               | `navigator.maxTouchPoints`                                                              | Phone, tablet or desktop                                                                         |
| Display preferences | `prefers-color-scheme`, `prefers-reduced-motion`, `prefers-contrast`                    | Your settings. Accessibility settings can hint at health needs; flagged as sensitive in the copy |
| Privacy signals     | `navigator.globalPrivacyControl`, `navigator.doNotTrack`, `navigator.cookieEnabled`     | Whether you asked sites not to track you (ironically, also a signal)                             |
| Connection          | `navigator.connection.effectiveType` (Chromium)                                         | Your rough network type                                                                          |
| Permission states   | `navigator.permissions.query` for geolocation, camera, microphone, notifications        | Whether _this site_ already has access. Querying state never prompts                             |

### Potential: any site could get this, but this panel deliberately does not

Shown as text only. **Nothing in this list is computed**, because computing it
would be fingerprinting (G2) or a server lookup (G3).

- Your IP address and approximate location: every server you contact sees it. This panel does not look it up.
- Canvas, WebGL and audio rendering fingerprints, GPU model, installed fonts: tiny differences that identify a device across sites.
- High-entropy client hints (exact OS version, device model): available on request in Chromium browsers.
- Precise location, camera, microphone: only after you allow a permission prompt.
- Cookies and storage that recognise you when you come back, and third-party scripts that do this across sites.
- How you type, scroll and move the mouse.

### Unknown: cannot be seen from a browser at all

- What a website's servers store about you, and for how long.
- Whether it is combined with data from other sites into a profile.
- Who it is shared with or sold to.

Closing line (draft): _"AskMI can't fix what websites see about your browser.
It changes what you have to hand over when a site asks who you are: a proof
instead of your data."_ This keeps the claim within what the wallet does.

### Honesty notes for the copy

- The wallet is a website too, so it can read the _Observed_ list as well. Say so: "This page read these values just now to show them to you. It keeps none of them."
- No percentages, scores, colours ranking "risk", or "you are unique" claims (the last needs a reference population we don't have).

## 4. Existing code this must not reuse: `PrivacyAuditService`

`src/apps/wallet-pwa/src/services/PrivacyAuditService.ts` is labelled in its
own code as a **mock**. It sniffs the user agent and then asserts things about
remote systems with confidence numbers, for example "Google Chrome: HIGH, Chrome
Sync & FLoC/Topics" at `confidence: 99`, "Android: OS-level telemetry active" at
`confidence: 95`, "Windows Telemetry" and "Apple ID telemetry", plus a
`privacyScore`. It is used by `PrivacyAuditModal`, and its
output flows into identity-firewall metadata (`source: 'privacy_audit_service'`
in `WalletService.mapTrackingPointToIdentityMetadata`).

That breaks the reference principle (_don't claim what happens on remote
servers_) and G2 (no score). The panel therefore **does not import or extend
it**. What happens to the service itself is decision D2 below.

## 5. Shape of the implementation (left to the builder within these bounds)

- `src/apps/wallet-pwa/src/utils/visible-signals.ts`: a pure `collectVisibleSignals(env)` that takes `navigator`, `screen`, `matchMedia` and `Intl` as arguments (testable in jsdom) and returns `VisibleSignal[]`, each with `{ id, layer, label, value?, reveals, sensitive? }`. The Potential and Unknown lists are static data in the same module.
- `src/apps/wallet-pwa/src/components/VisibilityPanel.tsx`: renders the three sections, collapsed by default, with "Hide" and an explanatory footer.
- Dismissed flag: `askmi.visibilityPanelDismissed` through the existing try/catch `readLocalFlag` / `writeLocalFlag` helpers (#222 pattern). It is a boolean only.
- One small PR: collector, panel, placement, CSS and tests.

## 6. Testing (TDD, test first)

- **Collector:** maps a stubbed environment to the expected items. Missing APIs give "not exposed". No item has an empty `reveals`. Every `layer` is one of the three.
- **G1:** after render and hide, nothing new in localStorage except the dismissed flag. IndexedDB, the audit service and `WalletService` are not called.
- **G2:** a structural check that `visible-signals.ts` has no import from `services/`. No numeric score and no hash anywhere in the output.
- **G3:** spies on `fetch`, `XMLHttpRequest.open`, `navigator.sendBeacon`, `WebSocket` and `RTCPeerConnection` stay uncalled while collecting and rendering.
- **G5:** collapsed by default; hide persists; reopening from Settings works.
- **Browser check:** real Chrome via Playwright at desktop and phone width. Verify values show, nothing is requested over the network (network log), and the dismissed state survives a reload.

## 7. Decisions

### Mine (builder may revisit)

- **Show real values, not categories.** It's local and it's the "aha". The full user-agent string sits behind a "show full" toggle.
- **No parsing of the user agent into marketing names.** Raw low-entropy fields only, because parsing is heuristic and would need its own honesty caveats.
- **English copy**, matching the rest of the wallet. German is part of the existing mixed-language backlog item.
- **Collapsed by default** with a one-line teaser ("What every website already sees about this browser"), so the welcome flow stays short.
- **No export or "copy report"** in v1. Exporting is a retention path, which conflicts with G1's spirit.

### Yours (change what gets built)

- **D1. Placement.** Recommended: a collapsible section on the **Welcome** card (first run, before account creation), the same on the **Locked** card, plus a permanent entry in **Settings**. _Not_ on the landing page in v1: the landing page speaks to identity teams (B2B), while the panel speaks to the person holding the device. The alternative is to add it to the landing page as the demo opener.
- **D2. `PrivacyAuditService`.** Recommended: leave it out of this track, but open a separate issue to bring it in line with the same principle (remove claims about remote systems, remove the score, relabel as illustrative), because it currently feeds identity-firewall metadata. Alternatives: replace it as part of this track (larger PR, touches transaction flow), or leave it as is.

## 8. Out of scope

- The companion "what we already know about this _verifier_ from our own past interactions" (Requests/Trace, #213 surfaces). It shares §3's taxonomy but needs its own note, because it reads the wallet's own stored history.
- Any change to the existing anti-fingerprinting transport measures (padding, jitter, uniform headers; U-22/U-23).
- Any dependency on, or code shared with, the Transparency-Layer extension.
