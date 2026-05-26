#!/usr/bin/env sh
set -eu

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        echo "docker compose or docker-compose is required" >&2
        exit 1
    fi
}

cleanup() {
    compose down >/dev/null 2>&1 || true
}

trap cleanup EXIT

services="verifier-backend issuer-mock wallet-pwa verifier-frontend proxy"
wait_seconds="${MITCH_VERIFY_WAIT_SECONDS:-15}"

echo "Checking docker-compose configuration..."
compose config --quiet

echo "Building Docker images..."
compose build

echo "Starting containers..."
compose up -d

echo "Waiting ${wait_seconds}s for services to initialize..."
sleep "$wait_seconds"

echo "Container status:"
compose ps

for service in $services; do
    container_id="$(compose ps -q "$service" | head -n 1)"
    if [ -z "$container_id" ]; then
        echo "No container found for service '$service'." >&2
        compose logs
        exit 1
    fi

    running="$(docker inspect -f '{{.State.Running}}' "$container_id")"
    if [ "$running" != "true" ]; then
        echo "Service '$service' is not running." >&2
        compose logs
        exit 1
    fi
done

echo "Deployment verification successful."
