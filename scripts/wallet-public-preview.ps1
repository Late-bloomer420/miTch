[CmdletBinding()]
param(
    [int]$PreviewPort = 4173,
    [int]$VerifierPort = 3004,
    [int]$IssuerPort = 3005,
    [string]$PreviewHost = "127.0.0.1",
    [string]$CloudflaredPath = (Join-Path $env:TEMP "cloudflared.exe"),
    [switch]$NoBuild,
    [switch]$Detach,
    [switch]$KeepExisting
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CloudflaredDownloadUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$StatePath = Join-Path $env:TEMP "askmi-$RunId-wallet-public-preview.state.log"

function Write-State {
    param([string]$Message)
    $line = "$(Get-Date -Format o) $Message"
    Add-Content -LiteralPath $StatePath -Value $line
    Write-Output $Message
}

function Stop-PortOwner {
    param([int]$Port)

    Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        Where-Object { $_ } |
        ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
}

function Stop-CloudflaredForPort {
    param([int]$Port)

    Get-CimInstance Win32_Process -Filter "name = 'cloudflared.exe'" |
        Where-Object { $_.CommandLine -match "127\.0\.0\.1:$Port|localhost:$Port|:$Port" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
}

function Wait-ForHttp {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for $Url"
}

function Wait-ForTunnelUrl {
    param(
        [string]$LogPath,
        [int]$TimeoutSeconds = 75
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $content = Get-Content -Raw $LogPath -ErrorAction SilentlyContinue
        if ($null -eq $content) {
            $content = ""
        }
        $match = [regex]::Match($content, "https://[a-z0-9-]+\.trycloudflare\.com")
        if ($match.Success) {
            return $match.Value
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for cloudflared URL. See $LogPath"
}

function Start-LoggedPowerShell {
    param(
        [string]$Name,
        [string]$Command
    )

    $log = Join-Path $env:TEMP "askmi-$RunId-$Name.log"
    $err = Join-Path $env:TEMP "askmi-$RunId-$Name.err.log"
    Write-State "Starting $Name..."

    $process = Start-Process -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $Command) `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $log `
        -RedirectStandardError $err `
        -WindowStyle Hidden `
        -PassThru

    return [pscustomobject]@{ Process = $process; Log = $log; Err = $err }
}

function Start-CloudflareTunnel {
    param(
        [string]$Name,
        [string]$LocalUrl
    )

    $log = Join-Path $env:TEMP "askmi-$RunId-cloudflared-$Name.log"
    $err = Join-Path $env:TEMP "askmi-$RunId-cloudflared-$Name.err.log"
    Write-State "Starting Cloudflare tunnel $Name -> $LocalUrl..."

    $process = Start-Process -FilePath $CloudflaredPath `
        -ArgumentList @("tunnel", "--metrics", "127.0.0.1:0", "--url", $LocalUrl) `
        -RedirectStandardOutput $log `
        -RedirectStandardError $err `
        -WindowStyle Hidden `
        -PassThru

    $publicUrl = Wait-ForTunnelUrl -LogPath $err
    Write-State "Cloudflare tunnel $Name is ready: $publicUrl"
    return [pscustomobject]@{ Process = $process; Url = $publicUrl; Log = $log; Err = $err }
}

Set-Location $RepoRoot

if (!(Test-Path $CloudflaredPath)) {
    Invoke-WebRequest -UseBasicParsing -Uri $CloudflaredDownloadUrl -OutFile $CloudflaredPath -TimeoutSec 120
}

if (-not $KeepExisting) {
    foreach ($port in @($PreviewPort, $VerifierPort, $IssuerPort)) {
        Stop-PortOwner -Port $port
        Stop-CloudflaredForPort -Port $port
    }
}

$issuerLocalUrl = "http://${PreviewHost}:${IssuerPort}"
$verifierLocalUrl = "http://${PreviewHost}:${VerifierPort}"
$previewLocalUrl = "http://${PreviewHost}:${PreviewPort}"

$started = New-Object System.Collections.Generic.List[object]

try {
    $issuer = Start-LoggedPowerShell `
        -Name "issuer-mock-$IssuerPort" `
        -Command "`$env:PORT='$IssuerPort'; pnpm --filter @askmi/issuer-mock dev"
    $started.Add($issuer)
    Wait-ForHttp -Url "$issuerLocalUrl/health"

    $verifier = Start-LoggedPowerShell `
        -Name "verifier-backend-$VerifierPort" `
        -Command "`$env:PORT='$VerifierPort'; `$env:TRUST_PROXY='1'; `$env:TRUST_PROXY_HOPS='1'; pnpm --filter verifier-backend dev"
    $started.Add($verifier)
    Wait-ForHttp -Url "$verifierLocalUrl/health"

    $issuerTunnel = Start-CloudflareTunnel -Name "issuer-$IssuerPort" -LocalUrl $issuerLocalUrl
    $started.Add($issuerTunnel)

    $verifierTunnel = Start-CloudflareTunnel -Name "verifier-$VerifierPort" -LocalUrl $verifierLocalUrl
    $started.Add($verifierTunnel)

    $env:ASKMI_DEV_HTTPS = "0"
    $env:VITE_ISSUER_URL = $issuerTunnel.Url
    $env:VITE_VERIFIER_URL = "$($verifierTunnel.Url)/present"

    if (-not $NoBuild) {
        pnpm --filter @askmi/wallet-pwa build
    }

    $preview = Start-LoggedPowerShell `
        -Name "wallet-preview-$PreviewPort" `
        -Command "`$env:ASKMI_DEV_HTTPS='0'; pnpm --filter @askmi/wallet-pwa preview -- --host $PreviewHost --port $PreviewPort --strictPort"
    $started.Add($preview)
    Wait-ForHttp -Url "$previewLocalUrl/?demo=wallet"

    $walletTunnel = Start-CloudflareTunnel -Name "wallet-$PreviewPort" -LocalUrl $previewLocalUrl
    $started.Add($walletTunnel)

    $demoUrl = "$($walletTunnel.Url)/?demo=wallet"

    Write-Output ""
    Write-Output "AskMI Wallet public preview is ready:"
    Write-Output "ASKMI_WALLET_PUBLIC_URL=$demoUrl"
    Write-Output "ASKMI_VERIFIER_PUBLIC_URL=$($verifierTunnel.Url)"
    Write-Output "ASKMI_ISSUER_PUBLIC_URL=$($issuerTunnel.Url)"
    Write-Output ""
    Write-Output "Keep this terminal open. Press Ctrl+C to stop preview, issuer, verifier, and tunnels."

    if ($Detach) {
        Write-Output "Detached. Stop the printed service processes or rerun without -KeepExisting to clean ports."
        exit 0
    }

    while ($true) {
        Start-Sleep -Seconds 3600
    }
}
catch {
    Write-Error $_
    throw
}
finally {
    if (-not $Detach) {
        foreach ($entry in $started) {
            if ($entry.Process -and $entry.Process.Id) {
                Stop-Process -Id $entry.Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        foreach ($port in @($PreviewPort, $VerifierPort, $IssuerPort)) {
            Stop-PortOwner -Port $port
            Stop-CloudflaredForPort -Port $port
        }
    }
}
