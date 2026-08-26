# AskMI repository ecosystem

## Canonical repository

[`Late-bloomer420/miTch`](https://github.com/Late-bloomer420/miTch) is the canonical active AskMI implementation and source of truth for product code, packages, current documentation, security fixes, and releases.

The repository name remains `miTch` for compatibility. The canonical product and package brand is **AskMI** / `@askmi/*`.

## Related repositories

Related repositories are not automatically production components of AskMI. Their README should point here and state one of these roles before reuse:

| Repository | Intended disposition |
|---|---|
| `M.I.T.C.H.` | Historical concept/agent-orchestration exploration; archive or mark historical after salvaging unique design material. |
| `mitch-temp` | Historical predecessor; archive and redirect to the canonical repository. |
| `miTch-Transparency-Layer` | Separate experimental browser-extension prototype; keep separate only with an explicit experimental integration contract. |
| `miTch---Policy-Enforcement-Layer` | Placeholder/historical repository; archive and redirect. |
| `mi.login` | Private scratch/orphan repository; review privately, then either migrate unique work or archive. |

Archiving, changing descriptions, or closing repositories is an external action and must be performed only after maintainer review.

## Open-PR disposition on the canonical repository

As reviewed on 2026-08-19:

- **#140 Dependabot/PostCSS:** superseded by the broader dependency hardening on the truth/readiness RC branch; close only after the replacement lands.
- **#139 wallet test app/delegation architecture:** conflicting and far behind `master`; do not merge wholesale. Salvage independently reviewed GNAP/AI-Guardian documents or wallet changes as small current branches.
- **#138 ADOPT-0a/0b live-verification docs:** the dated evidence and verified facts are reconciled into this RC branch under the current maturity/evidence rules. After #141 lands, close #138 as superseded; do not merge its older `STATE.md` or `BACKLOG.md` copies over the RC baseline.
- **#130, #129, #105:** stale/conflicting. Confirm whether useful changes already landed; salvage only minimal missing commits, then close with a clear explanation.

## Consolidation rule

New AskMI product work belongs in the canonical monorepo unless it has an explicit reason to be independently versioned, released, secured, and maintained. Design experiments should be labelled experimental and must not create competing product truth sources.
