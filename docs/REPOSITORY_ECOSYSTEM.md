# AskMI repository ecosystem

First recorded 2026-08-19 on the #141 branch; carried to `master` on 2026-10-25. The related-repository roles below are intended dispositions, not completed actions.

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

## Open-PR disposition (historical)

The open-PR disposition recorded here on 2026-08-19 (#141) is mostly settled: #105 and #139 are closed, #130 and #138 are merged, and #141's code hardening landed through #195. #129 and #140 were still open on 2026-10-25. Current PR state lives on GitHub, not in this file.

## Consolidation rule

New AskMI product work belongs in the canonical monorepo unless it has an explicit reason to be independently versioned, released, secured, and maintained. Design experiments should be labelled experimental and must not create competing product truth sources.
