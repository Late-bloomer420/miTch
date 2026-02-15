# 90 — No Silent Allow Assertion

Stand: 2026-02-11

## Why
For privacy/security-critical verification, uncertain resolver outcomes must not degrade into implicit allow behavior.

## Assertion added
In resolver quorum tests, repeated mismatch/no-quorum checks must continue to return no key (`null`).

## Security interpretation
- No quorum => no key
- no key => deny-biased verification path
- therefore no silent allow during resolver disagreement incidents
