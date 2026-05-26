$ErrorActionPreference = 'Stop'

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ComposeArgs)

    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        & docker-compose @ComposeArgs
        return
    }

    & docker compose @ComposeArgs
}

$services = @(
    'verifier-backend',
    'issuer-mock',
    'wallet-pwa',
    'verifier-frontend',
    'proxy'
)

$waitSeconds = if ($env:MITCH_VERIFY_WAIT_SECONDS) {
    [int]$env:MITCH_VERIFY_WAIT_SECONDS
} else {
    15
}

try {
    Write-Host 'Checking docker-compose configuration...'
    Invoke-Compose config --quiet

    Write-Host 'Building Docker images...'
    Invoke-Compose build

    Write-Host 'Starting containers...'
    Invoke-Compose up -d

    Write-Host "Waiting $waitSeconds seconds for services to initialize..."
    Start-Sleep -Seconds $waitSeconds

    Write-Host 'Container status:'
    Invoke-Compose ps

    foreach ($service in $services) {
        $containerId = (Invoke-Compose ps -q $service | Select-Object -First 1)
        if (-not $containerId) {
            throw "No container found for service '$service'."
        }

        $running = docker inspect -f '{{.State.Running}}' $containerId
        if ($running -ne 'true') {
            throw "Service '$service' is not running."
        }
    }

    Write-Host 'Deployment verification successful.'
} catch {
    Write-Error $_
    Invoke-Compose logs
    exit 1
} finally {
    Write-Host 'Stopping deployment stack...'
    Invoke-Compose down
}
