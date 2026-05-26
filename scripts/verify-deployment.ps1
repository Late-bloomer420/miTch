# miTch Deployment Verification Script

Write-Host "🚀 Starting miTch Deployment Verification..." -ForegroundColor Cyan

# 1. Build the images
Write-Host "📦 Building Docker images..." -ForegroundColor Yellow
docker-compose build

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}

# 2. Start the stack in background
Write-Host "🏃 Starting containers..." -ForegroundColor Yellow
docker-compose up -d

# 3. Wait for services to be ready
Write-Host "⏳ Waiting for services to initialize (15s)..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# 4. Check container status
Write-Host "🔍 Checking container health..." -ForegroundColor Yellow
docker-compose ps

# 5. Verify internal connectivity
$running = (docker-compose ps --format json | ConvertFrom-Json | Where-Object { $_.State -eq "running" }).Count
if ($running -ge 3) {
    Write-Host "✅ At least 3 services are running." -ForegroundColor Green
} else {
    Write-Host "❌ Deployment failed: Only $running services are running." -ForegroundColor Red
    docker-compose logs
    docker-compose down
    exit 1
}

Write-Host "✅ Deployment verification successful!" -ForegroundColor Green

# 6. Cleanup
Write-Host "🧹 Cleaning up..." -ForegroundColor Yellow
docker-compose down
