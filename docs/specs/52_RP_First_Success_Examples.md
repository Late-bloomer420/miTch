# 52 — RP First Success Examples

## PowerShell example
```powershell
$token = "dev-secret"
$sample = Invoke-WebRequest -UseBasicParsing http://localhost:8080/test-request | Select-Object -ExpandProperty Content

Invoke-WebRequest -UseBasicParsing http://localhost:8080/verify `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{"Authorization"="Bearer $token";"x-correlation-id"="rp1-first-success"} `
  -Body $sample | Select-Object -ExpandProperty Content
```

Expected: `decision = ALLOW` (when LOCAL_TEST_KEYS=1 and audience matches).

## Auth failure example
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/verify `
  -Method POST `
  -ContentType "application/json" `
  -Body $sample
```
Expected: `401 unauthorized`

## Audience mismatch example
Set `RUNTIME_AUDIENCE` to another value or modify request audience.
Expected: `DENY_BINDING_AUDIENCE_MISMATCH`
