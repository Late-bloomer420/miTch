# ============================================================
#  miTch - E2E Demo Start Script (Windows PowerShell)
#  Usage:  .\dev-demo.ps1
#  Stop:   Ctrl+C or close separate shell windows
# ============================================================

$ErrorActionPreference = "Stop"

# --- Color helper function ---
function Write-Color($Text, $Color = "White") {
  Write-Host $Text -ForegroundColor $Color
}

# --- Header ---
Clear-Host
Write-Color "======================================================" Cyan
Write-Color "|           miTch - Personal Trust Hub               |" Cyan
Write-Color "|                  E2E Demo Mode                     |" Cyan
Write-Color "======================================================" Cyan
Write-Host ""

# --- Working Directory ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir
Write-Color "[DIR] Working directory: $ScriptDir" Gray

# --- Reactome Database Status & Logging ---
Write-Color "[REACTOME] Checking Reactome database status..." Cyan
$env:Path = "C:\Users\Lenovo\bin;$env:Path"
if (Get-Command uv -ErrorAction SilentlyContinue) {
  try {
    uv run C:\Users\Lenovo\.gemini\config\plugins\science\skills\reactome_database\scripts\reactome_analysis.py db-version --output "$ScriptDir\src\apps\verifier-demo\frontend\src\data\reactome-version.json" *>$null
    $VersionContent = Get-Content "$ScriptDir\src\apps\verifier-demo\frontend\src\data\reactome-version.json" -Raw | ConvertFrom-Json
    $DbVer = $VersionContent.database_version
    Write-Color "[REACTOME] Online - Reactome Database Version: $DbVer" Green
    
    # Save an audit log in the conversation folder
    $LogPath = "C:\Users\Lenovo\.gemini\antigravity\brain\29192b9a-834a-4f54-8229-b1c344912194\reactome_verification.log"
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Reactome Database verified. Version: $DbVer" | Out-File -FilePath $LogPath -Append -Encoding utf8
  } catch {
    Write-Color "[REACTOME] Offline or script error: $_" Yellow
  }
} else {
  Write-Color "[REACTOME] uv not on path, skipping status check." Yellow
}


# --- Check pnpm ---
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
  Write-Color "[ERROR] pnpm not found. Install via: npm i -g pnpm" Red
  exit 1
}

# --- Launching Services in background windows ---
$jobs = @()

Write-Color "[START] Starting Issuer-Mock     (port 3005)..." Cyan
$jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "Write-Host '[Issuer-Mock]' -ForegroundColor Cyan -NoNewline; pnpm --filter '@mitch/issuer-mock' dev" `
  -PassThru

Start-Sleep -Milliseconds 800

Write-Color "[START] Starting Verifier-Backend (port 3004)..." Magenta
$jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "Write-Host '[Verifier-Backend]' -ForegroundColor Magenta -NoNewline; pnpm --filter 'verifier-backend' dev" `
  -PassThru

Start-Sleep -Milliseconds 800

Write-Color "[START] Starting Wallet PWA       (port 5174)..." Green
$jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "Write-Host '[Wallet-PWA]' -ForegroundColor Green -NoNewline; pnpm --filter '@mitch/wallet-pwa' dev" `
  -PassThru

Start-Sleep -Milliseconds 800

# Verifier-Frontend optional
if (Test-Path "src\apps\verifier-demo\frontend\package.json") {
  Write-Color "[START] Starting Verifier-Frontend (port 5175)..." Yellow
  $jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd src\apps\verifier-demo\frontend; pnpm dev --port 5175" `
    -PassThru
}

# --- Status overview ---
Write-Host ""
Write-Color "======================================================" Blue
Write-Color "[STATUS] miTch Services starting up:" White
Write-Host ""
Write-Color "  *  Issuer-Mock        ->  http://localhost:3005" Cyan
Write-Color "  *  Verifier-Backend   ->  http://localhost:3004" Magenta
Write-Color "  *  Wallet PWA         ->  http://localhost:5174  <- Start here" Green
if (Test-Path "src\apps\verifier-demo\frontend\package.json") {
  Write-Color "  *  Verifier-Frontend  ->  http://localhost:5175" Yellow
}
Write-Host ""
Write-Color "[FLOW] E2E Flow:" White
Write-Color "   Wallet (5174) -> 'Prove Age' -> Issuer (3005) -> JWT VC" Gray
Write-Color "   Wallet -> Present -> Verifier-Backend (3004/present)" Gray
Write-Host ""
Write-Color "[INFO] WebAuthn works on localhost without HTTPS" Gray
Write-Color "[STOP] Close the spawned terminal windows to stop services." Gray
Write-Color "======================================================" Blue

# Open Browser (optional, after 3 seconds when ready)
Start-Sleep -Seconds 3
Start-Process "http://localhost:5174"
