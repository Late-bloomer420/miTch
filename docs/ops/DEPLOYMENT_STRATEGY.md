# Deployment Strategy: Sovereign Pilot Stack

miTch targets privacy-preserving verification with fail-closed policy decisions. The deployment model should preserve that design by keeping verifier, issuer mock, wallet UI, and audit-relevant logs under the operator's control. This document describes the initial Docker Compose pilot stack; it is not a claim of legal certification or full EUDI/eIDAS compliance.

## Deployment Model

| Area | Sovereign Docker pilot | Managed public cloud |
| :--- | :--- | :--- |
| Data location | Operator-controlled host or EU-based provider | Depends on provider region, support access, and subprocessors |
| Key management | Can be integrated with local HSM or operator-managed vault | Often depends on managed KMS and cloud IAM |
| Auditability | Local control over service logs, proxy logs, and retention | Limited to provider controls and exported logs |
| Portability | Compose-first, suitable for later Kubernetes migration | Higher risk of provider-specific assumptions |
| Compliance posture | Compliance-oriented infrastructure baseline | Requires additional transfer, access, and processor analysis |

## Stack

- `verifier-backend`: verifier API on port `3004`.
- `issuer-mock`: pilot issuer on port `3005`.
- `wallet-pwa`: wallet UI served as static assets.
- `verifier-frontend`: verifier demo UI served as static assets.
- `proxy`: Caddy reverse proxy for local hostnames and future TLS termination.
- `issuer-mock/public/v1/eudi-lotl.json`: local pilot trust-list fixture used by the verifier default `MITCH_TSL_URL`.

Default local site addresses are `http://wallet.localhost`, `http://verifier.localhost`, `http://issuer.localhost`, and `http://api.localhost`. Override them with `MITCH_WALLET_SITE`, `MITCH_VERIFIER_SITE`, `MITCH_ISSUER_SITE`, and `MITCH_API_SITE` when enabling real TLS hostnames.

## Run

```bash
docker-compose up --build
```

For a real pilot, set explicit public URLs before building the static frontends:

```bash
MITCH_WALLET_URL=https://wallet.example.eu \
MITCH_WALLET_SITE=https://wallet.example.eu \
MITCH_VERIFIER_API_URL=https://api.example.eu/verifier \
MITCH_VERIFIER_PRESENT_URL=https://api.example.eu/verifier/present \
MITCH_VERIFIER_SITE=https://verifier.example.eu \
MITCH_API_SITE=https://api.example.eu \
MITCH_ISSUER_URL=https://api.example.eu/issuer \
MITCH_ISSUER_CREDENTIAL_URL=https://api.example.eu/issuer/credential \
MITCH_ISSUER_SITE=https://issuer.example.eu \
MITCH_TSL_PUBLIC_URL=https://api.example.eu/issuer/v1/eudi-lotl.json \
docker-compose up --build
```

For a local smoke test with cleanup:

```bash
./scripts/verify-deployment.sh
```

On Windows PowerShell:

```powershell
.\scripts\verify-deployment.ps1
```

## Production Hardening Still Required

- Replace demo trust-list URLs with an operator-controlled, monitored source.
- Back issuer and verifier keys with an HSM or equivalent managed key boundary.
- Configure durable audit storage and retention before processing real users.
- Review CORS origins and hostnames for each pilot deployment.
- Keep compliance status in the EUDI/EHDS matrices separate from deployment readiness.
