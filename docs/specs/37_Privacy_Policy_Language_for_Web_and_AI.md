# 37 — Privacy Policy Language (Web + AI) v0 (Concept)

Stand: 2026-02-11

## Purpose
Define a shared policy grammar that can govern both web data requests and AI tool/model I/O.

---

## Core entities
- **Subject:** user/device/workspace context
- **Requester:** website/service/model/tool
- **Data Class:** PII, secret, business-sensitive, public
- **Action:** allow, deny, notify, transform
- **Purpose:** explicit usage intent
- **Retention:** TTL/storage constraints

---

## Rule shape (concept)
```yaml
ruleId: R-001
scope: web|ai|global
requester: "example.com" | "model:vendor/model-name" | "*"
dataClass: [PII, SECRET]
purpose: "age_verification" | "support_ticket" | "*"
action: deny|allow|notify|transform
transformProfile: "semantic-min-v1" # optional
retention:
  maxTtlSec: 0
  store: none|local|remote
```

---

## Semantics
- Unknown requester/dataClass/purpose => deny or notify+deny (policy-defined fail-closed)
- `transform` requires deterministic profile and receipt logging
- `allow` without purpose is invalid
- `remote` retention requires explicit approved profile

---

## Example rules
1. Deny external model access to secrets:
```yaml
scope: ai
requester: "model:*"
dataClass: [SECRET]
purpose: "*"
action: deny
```

2. Allow age predicate exchange but never raw DOB:
```yaml
scope: web
requester: "rp:age-gate"
dataClass: [PII]
purpose: "age_verification"
action: transform
transformProfile: "predicate-age-gte18"
retention:
  maxTtlSec: 0
  store: none
```

3. Notify on unclassified web requests:
```yaml
scope: web
requester: "*"
dataClass: [UNKNOWN]
purpose: "*"
action: notify
```

---

## Next step
Map this language to executable policy manifests after Core MVP reaches stable operations.
