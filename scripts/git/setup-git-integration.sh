#!/usr/bin/env bash
set -euo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "❌ Not inside a git repository."
  exit 1
fi

git config core.hooksPath .githooks
git config fetch.prune true
git config pull.ff only

echo "✅ Git integration configured:"
echo "   - core.hooksPath=.githooks"
echo "   - fetch.prune=true"
echo "   - pull.ff=only"
