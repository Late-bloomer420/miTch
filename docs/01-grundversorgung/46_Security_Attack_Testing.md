# 46 — Security Attack Testing (Current Scope)

## Important
This is not "all possible attacks" coverage. It is a practical pilot-oriented baseline.

## Included now
- Replay attack checks
- Hash mismatch tampering
- Audience mismatch
- Revoked/missing key handling
- Unauthorized request rejection
- Burst/swarm simulation (same requester + distributed requester patterns)

## Swarm test command
```powershell
cd C:\Users\Admin\Documents\miTch
npm run swarm:test
```

## Expected interpretation
- Same requester burst should trigger rate-limit denies.
- Distributed requester swarm should now also trigger denies via global request budget baseline.

## Remaining hardening suggestions
1. Add global concurrency caps and queue protections.
2. Add IP/network-level limits (outside app layer).
3. Add challenge/escalation path on anomaly spikes.
4. Track requester reputation/risk score (privacy-preserving design needed).

## Pilot safety posture
Use current results as evidence + backlog input, not as proof of complete security.
