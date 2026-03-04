# ============================================================
#  miTch — E2E Demo Start Script (Windows PowerShell)
#  Usage:  .\dev-demo.ps1
#  Stop:   Ctrl+C  oder Fenster schließen
# ============================================================

$ErrorActionPreference = "Stop"

# ── Farben-Hilfsfunktion ─────────────────────────────────────
function Write-Color($Text, $Color = "White") {
  Write-Host $Text -ForegroundColor $Color
}

# ── Header ───────────────────────────────────────────────────
Clear-Host
Write-Color "╔══════════════════════════════════════════════════════╗" Cyan
Write-Color "║           miTch — Personal Trust Hub                ║" Cyan
Write-Color "║                  E2E Demo Mode                      ║" Cyan
Write-Color "╚══════════════════════════════════════════════════════╝" Cyan
Write-Host ""

# ── Working Directory ────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir
Write-Color "📁  Working directory: $ScriptDir" Gray

# ── pnpm prüfen ──────────────────────────────────────────────
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
  Write-Color "❌  pnpm not found. Install via: npm i -g pnpm" Red
  exit 1
}

# ── Services als separate Fenster starten ────────────────────
$jobs = @()

Write-Color "▶  Starting Issuer-Mock     (port 3005)..." Cyan
$jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "Write-Host '[Issuer-Mock]' -ForegroundColor Cyan -NoNewline; pnpm --filter '@mitch/issuer-mock' dev" `
  -PassThru

Start-Sleep -Milliseconds 800

Write-Color "▶  Starting Verifier-Backend (port 3004)..." Magenta
$jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "Write-Host '[Verifier-Backend]' -ForegroundColor Magenta -NoNewline; pnpm --filter 'verifier-backend' dev" `
  -PassThru

Start-Sleep -Milliseconds 800

Write-Color "▶  Starting Wallet PWA       (port 5174)..." Green
$jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "Write-Host '[Wallet-PWA]' -ForegroundColor Green -NoNewline; pnpm --filter '@mitch/wallet-pwa' dev" `
  -PassThru

Start-Sleep -Milliseconds 800

# Verifier-Frontend optional
if (Test-Path "verifier-demo\frontend\package.json") {
  Write-Color "▶  Starting Verifier-Frontend (port 5175)..." Yellow
  $jobs += Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd verifier-demo\frontend; pnpm dev" `
    -PassThru
}

# ── Status ───────────────────────────────────────────────────
Write-Host ""
Write-Color "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" Blue
Write-Color "🚀  miTch Services starting up:" White
Write-Host ""
Write-Color "  ●  Issuer-Mock        →  http://localhost:3005" Cyan
Write-Color "  ●  Verifier-Backend   →  http://localhost:3004" Magenta
Write-Color "  ●  Wallet PWA         →  http://localhost:5174  ← Start here" Green
if (Test-Path "verifier-demo\frontend\package.json") {
  Write-Color "  ●  Verifier-Frontend  →  http://localhost:5175" Yellow
}
Write-Host ""
Write-Color "🔄  E2E Flow:" White
Write-Color "   Wallet (5174) → 'Prove Age' → Issuer (3005) → JWT VC" Gray
Write-Color "   Wallet → Present → Verifier-Backend (3004/present)" Gray
Write-Host ""
Write-Color "💡  WebAuthn works on localhost without HTTPS ✓" Gray
Write-Color "⛔  Close the terminal windows to stop all services." Gray
Write-Color "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" Blue

# Browser öffnen (optional, nach 3s wenn Services bereit)
Start-Sleep -Seconds 3
Start-Process "http://localhost:5174"
