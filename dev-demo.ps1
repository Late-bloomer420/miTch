# Compatibility entrypoint: the shared launcher owns ports, environment and cleanup.
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try { pnpm demo @args; exit $LASTEXITCODE } finally { Pop-Location }
