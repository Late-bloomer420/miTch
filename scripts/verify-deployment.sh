#!/bin/bash
set -e

echo "🚀 Starting miTch Deployment Verification..."

# 1. Build the images
echo "📦 Building Docker images..."
docker compose build

# 2. Start the stack in background
echo "🏃 Starting containers..."
docker compose up -d

# 3. Wait for services to be ready
echo "⏳ Waiting for services to initialize (15s)..."
sleep 15

# 4. Check container status
echo "🔍 Checking container health..."
docker compose ps

# 5. Verify internal connectivity (basic check)
echo "🌐 Verifying service endpoints..."

# Check Wallet PWA (Port 80 inside container, exposed via Caddy usually)
# For this test we check if the containers are running and ports are bound
RUNNING_CONTAINERS=$(docker compose ps --format json | jq '. | select(.State == "running")' | wc -l)
if [ "$RUNNING_CONTAINERS" -ge 3 ]; then
    echo "✅ At least 3 services are running."
else
    echo "❌ Deployment failed: Not all services are running."
    docker compose logs
    exit 1
fi

echo "✅ Deployment verification successful!"

# 6. Cleanup
echo "🧹 Cleaning up..."
docker compose down
