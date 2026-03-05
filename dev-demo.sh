#!/usr/bin/env bash
# ============================================================
#  miTch — E2E Demo Start Script
#  Startet alle Services parallel mit farbigem Log-Output
#  Usage:  bash dev-demo.sh
#  Stop:   Ctrl+C  (killt alle Child-Prozesse sauber)
# ============================================================

set -euo pipefail

# ── Farben ──────────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
BLUE="\033[0;34m"

# ── Prefix-Farben pro Service ────────────────────────────────
COLOR_ISSUER=$CYAN
COLOR_VERIFIER=$MAGENTA
COLOR_WALLET=$GREEN
COLOR_VERIFIER_FRONTEND=$YELLOW

# ── PIDs sammeln für Cleanup ─────────────────────────────────
PIDS=()

cleanup() {
  echo ""
  echo -e "${BOLD}${RED}⛔  Stopping all miTch services...${RESET}"
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && echo -e "   killed PID $pid"
    fi
  done
  echo -e "${BOLD}${GREEN}✅  All services stopped. Bye!${RESET}"
  exit 0
}

trap cleanup SIGINT SIGTERM

# ── Hilfsfunktion: Service starten mit farbigem Prefix ───────
start_service() {
  local label="$1"
  local color="$2"
  local filter="$3"
  local port="$4"

  echo -e "${BOLD}${color}▶  Starting ${label} on port ${port}...${RESET}"

  pnpm --filter "$filter" dev 2>&1 \
    | while IFS= read -r line; do
        echo -e "${color}[${label}]${RESET} $line"
      done &

  PIDS+=($!)
}

# ── Header ───────────────────────────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║           miTch — Personal Trust Hub                ║"
echo "║                  E2E Demo Mode                      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Working directory sicherstellen ──────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BOLD}📁  Working directory: ${SCRIPT_DIR}${RESET}"
echo ""

# ── Dependency check ─────────────────────────────────────────
if ! command -v pnpm &>/dev/null; then
  echo -e "${RED}❌  pnpm not found. Install via: npm i -g pnpm${RESET}"
  exit 1
fi

# ── Services starten ─────────────────────────────────────────
start_service "Issuer-Mock    " "$COLOR_ISSUER"           "@mitch/issuer-mock"   "3005"
sleep 0.5

start_service "Verifier-Backend" "$COLOR_VERIFIER"        "verifier-backend"     "3004"
sleep 0.5

start_service "Wallet-PWA     " "$COLOR_WALLET"           "@mitch/wallet-pwa"    "5173"
sleep 0.5

# Verifier-Frontend (optional — eigenes package.json in src/apps/verifier-demo/frontend)
if [ -f "src/apps/verifier-demo/frontend/package.json" ]; then
  echo -e "${BOLD}${COLOR_VERIFIER_FRONTEND}▶  Starting Verifier-Frontend (port 5175)...${RESET}"
  (cd src/apps/verifier-demo/frontend && npx vite --port 5175 2>&1 \
    | while IFS= read -r line; do
        echo -e "${COLOR_VERIFIER_FRONTEND}[Verifier-UI]${RESET} $line"
      done) &
  PIDS+=($!)
  sleep 0.5
fi

# ── Healthcheck: Warten bis Services ready sind ──────────────
echo ""
echo -e "${BOLD}⏳  Waiting for services to be ready...${RESET}"

wait_for_service() {
  local name="$1"
  local url="$2"
  local color="$3"
  local max_attempts=30
  local attempt=0
  while [ $attempt -lt $max_attempts ]; do
    if curl -sf "$url" > /dev/null 2>&1; then
      echo -e "  ${color}✅${RESET}  ${name} ready"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo -e "  ${RED}⚠️${RESET}  ${name} not responding after ${max_attempts}s"
  return 1
}

wait_for_service "Issuer-Mock"      "http://localhost:3005/health" "$COLOR_ISSUER"
wait_for_service "Verifier-Backend" "http://localhost:3004/health" "$COLOR_VERIFIER"
wait_for_service "Wallet-PWA"       "http://localhost:5173/"       "$COLOR_WALLET"

# ── Status-Übersicht ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}🚀  miTch Services starting up:${RESET}"
echo ""
echo -e "  ${COLOR_ISSUER}●${RESET}  Issuer-Mock        →  http://localhost:3005"
echo -e "  ${COLOR_VERIFIER}●${RESET}  Verifier-Backend   →  http://localhost:3004"
echo -e "  ${COLOR_WALLET}●${RESET}  Wallet PWA         →  http://localhost:5173  ← Start here"
if [ -f "src/apps/verifier-demo/frontend/package.json" ]; then
  echo -e "  ${COLOR_VERIFIER_FRONTEND}●${RESET}  Verifier-Frontend  →  http://localhost:5175"
fi
echo ""
echo -e "${BOLD}🔄  E2E Flow:${RESET}"
echo -e "   Wallet (5173) → 'Prove Age' → Issuer (3005) → JWT VC"
echo -e "   Wallet → Present → Verifier-Backend (3004/present)"
echo ""
echo -e "${BOLD}💡  WebAuthn:${RESET} Works on localhost without HTTPS ✓"
echo -e "${BOLD}⛔  Stop all:${RESET} Ctrl+C"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ── Warten bis alle Child-Prozesse beendet sind ──────────────
wait
