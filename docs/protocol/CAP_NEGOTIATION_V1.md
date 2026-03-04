# Capability Negotiation v1

## Scope

This spec defines wallet ↔ verifier capability negotiation for pilot flows. Implementations MUST evaluate handshake data locally (edge-first) and MUST fail closed.

## Handshake Format

Both parties MUST send the following object before proof exchange:

```json
{
  "protocolVersion": "1.0.0",
  "capabilities": {
    "layer0": true,
    "layer1": true,
    "revocation-online": true,
    "revocation-offline": false,
    "replay-protection": true,
    "step-up": true
  }
}
```

- `protocolVersion` MUST use semver-like `major.minor.patch`.
- A major-version mismatch MUST resolve to `DENY`.
- Malformed version strings MUST resolve to `DENY`.

## Capability Flags

The following flags are defined for v1:

- `layer0`
- `layer1`
- `revocation-online`
- `revocation-offline`
- `replay-protection`
- `step-up`

Security-critical flags are: `layer0`, `revocation-online`, `replay-protection`.

If either side lacks any security-critical flag, the wallet MUST return `DENY`.

## Downgrade Protection

A verifier MUST reject unsafe downgrade profiles. If both sides support a critical control and the negotiated/requested profile disables it, result MUST be `DENY`.

ReasonCode mapping MUST use existing `DenyReasonCode` values only:

- Version mismatch → `DENY_POLICY_UNSUPPORTED_VERSION`
- Critical capability mismatch → `DENY_POLICY_MISMATCH`
- Unsafe downgrade attempt → `DENY_BINDING_FAILED`
  - `// TODO(reason-code-gap):` introduce dedicated downgrade-attack deny code in a future revision.

## Fail-Closed Rule

Capability mismatch MUST resolve to `DENY` or `PROMPT` only; it MUST NEVER resolve to `ALLOW`.

For pilot v1 implementation, all mismatch classes resolve to `DENY`.
