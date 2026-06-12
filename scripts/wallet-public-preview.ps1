[CmdletBinding()]
param(
    [int]$PreviewPort = 4173,
    [string]$PreviewHost = "127.0.0.1",
    [string]$CloudflaredPath = (Join-Path $env:TEMP "cloudflared.exe"),
    [switch]$NoBuild,
    [switch]$Detach,
    [switch]$KeepExisting
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$PreviewUrl = "http://${PreviewHost}:${PreviewPort}"
$CloudflaredDownloadUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
$PreviewLog = Join-Path $env:TEMP "askmi-wallet-preview-${PreviewPort}.log"
$PreviewErr = Join-Path $env:TEMP "askmi-wallet-preview-${PreviewPort}.err.log"
$TunnelLog = Join-Path $env:TEMP "askmi-cloudflared-${PreviewPort}.log"
$TunnelErr = Join-Path $env:TEMP "askmi-cloudflared-${PreviewPort}.err.log"

function Stop-PortOwner {
    param([int]$Port)

    Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        Where-Object { $_ } |
        ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
}

function Stop-CloudflaredForPort {
    param([int]$Port)

    Get-CimInstance Win32_Process -Filter "name = 'cloudflared.exe'" |
        Where-Object { $_.CommandLine -match "127\.0\.0\.1:$Port|localhost:$Port|:$Port" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Wait-ForHttp {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 30
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
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $content = Get-Content -Raw $LogPath -ErrorAction SilentlyContinue
        $match = [regex]::Match($content, "https://[a-z0-9-]+\.trycloudflare\.com")
        if ($match.Success) {
            return $match.Value
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for cloudflared URL. See $TunnelErr"
}

Set-Location $RepoRoot

if (-not $KeepExisting) {
    Stop-PortOwner -Port $PreviewPort
    Stop-CloudflaredForPort -Port $PreviewPort
}

Remove-Item $PreviewLog, $PreviewErr, $TunnelLog, $TunnelErr -ErrorAction SilentlyContinue

if (-not $NoBuild) {
    pnpm --filter @askmi/wallet-pwa build
}

$previewCommand = "`$env:ASKMI_DEV_HTTPS='0'; pnpm --filter @askmi/wallet-pwa preview -- --host $PreviewHost --port $PreviewPort --strictPort"
$previewProcess = Start-Process -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $previewCommand) `
    -WorkingDirectory $RepoRoot `
    -RedirectStandardOutput $PreviewLog `
    -RedirectStandardError $PreviewErr `
    -WindowStyle Hidden `
    -PassThru

Wait-ForHttp -Url "$PreviewUrl/?demo=wallet"

if (!(Test-Path $CloudflaredPath)) {
    Invoke-WebRequest -UseBasicParsing -Uri $CloudflaredDownloadUrl -OutFile $CloudflaredPath -TimeoutSec 120
}

$tunnelProcess = Start-Process -FilePath $CloudflaredPath `
    -ArgumentList @("tunnel", "--url", $PreviewUrl) `
    -RedirectStandardOutput $TunnelLog `
    -RedirectStandardError $TunnelErr `
    -WindowStyle Hidden `
    -PassThru

$publicUrl = Wait-ForTunnelUrl -LogPath $TunnelErr
$demoUrl = "$publicUrl/?demo=wallet"

Write-Host ""
Write-Host "AskMI Wallet public preview is ready:"
Write-Host $demoUrl
Write-Output "ASKMI_WALLET_PUBLIC_URL=$demoUrl"
Write-Host ""
Write-Host "Local preview: $PreviewUrl/?demo=wallet"
Write-Host "Preview log: $PreviewLog"
Write-Host "Tunnel log:  $TunnelErr"
Write-Host ""

if ($Detach) {
    Write-Host "Detached. Stop process IDs $($previewProcess.Id) and $($tunnelProcess.Id) when done."
    exit 0
}

Write-Host "Keep this terminal open. Press Ctrl+C to stop preview and tunnel."

try {
    while ($true) {
        Start-Sleep -Seconds 3600
    }
}
finally {
    Stop-Process -Id $previewProcess.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $tunnelProcess.Id -Force -ErrorAction SilentlyContinue
}
