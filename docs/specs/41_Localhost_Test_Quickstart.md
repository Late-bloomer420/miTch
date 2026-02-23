# 41 — Localhost Test Quickstart

## Start server
```powershell
cd C:\Users\Admin\Documents\miTch
npm install
npm run compile
$env:RUNTIME_AUDIENCE="rp.example"
$env:LOCAL_TEST_KEYS="1"
$env:ALLOW_DEV_RESET="1"
$env:AUTH_TOKEN_REQUIRED="1"
$env:AUTH_TOKEN="dev-secret"
npm start
```

Server runs on `http://localhost:8080`.

Open in browser:
- `http://localhost:8080/` (service info)
- `http://localhost:8080/dashboard` (simple local dashboard)
- `http://localhost:8080/health`
- `http://localhost:8080/metrics`
- `http://localhost:8080/kpi` (derived KPI snapshot)
- `http://localhost:8080/audit/verify` (audit hash-chain integrity)

Authenticated ops endpoints:
- `POST /override`
- `POST /adjudicate`

## Health check
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/health | Select-Object -ExpandProperty Content
```

## Metrics check
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/metrics | Select-Object -ExpandProperty Content
```

## Metrics CSV export
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/metrics.csv | Select-Object -ExpandProperty Content
```

## DEV reset metrics
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/metrics/reset | Select-Object -ExpandProperty Content
```
(works only when `ALLOW_DEV_RESET=1`)

## ALLOW path test (signed request)
1) Generate signed request:
```powershell
$sample = Invoke-WebRequest -UseBasicParsing http://localhost:8080/test-request | Select-Object -ExpandProperty Content
```

2) Send it to verify:
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/verify `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{"x-correlation-id"="local-test-allow-1";"Authorization"="Bearer dev-secret"} `
  -Body $sample | Select-Object -ExpandProperty Content
```

Expected: `decision = ALLOW`

## DENY path quick test (tamper hash)
```powershell
$obj = $sample | ConvertFrom-Json
$obj.binding.requestHash = "tampered"
$bad = $obj | ConvertTo-Json -Depth 8

Invoke-WebRequest -UseBasicParsing http://localhost:8080/verify `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{"x-correlation-id"="local-test-deny-1";"Authorization"="Bearer dev-secret"} `
  -Body $bad | Select-Object -ExpandProperty Content
```

Expected: `DENY_BINDING_HASH_MISMATCH`

## Notes
- `LOCAL_TEST_KEYS=1` enables local signed-request generation for HTTP ALLOW-path testing.
- Disable it outside local/dev testing.
- If you see `EADDRINUSE` on port 8080, another server is already running. Stop it or use a different `PORT`.
