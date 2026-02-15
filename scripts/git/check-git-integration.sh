#!/usr/bin/env bash
set -euo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "❌ Not inside a git repository."
  exit 1
fi

hooks_path="$(git config --get core.hooksPath || true)"
fetch_prune="$(git config --get fetch.prune || true)"
pull_ff="$(git config --get pull.ff || true)"

status=0

if [[ "${hooks_path}" != ".githooks" ]]; then
  echo "❌ core.hooksPath is '${hooks_path:-<unset>}' (expected '.githooks')"
  status=1
else
  echo "✅ core.hooksPath is configured"
fi

if [[ "${fetch_prune}" != "true" ]]; then
  echo "❌ fetch.prune is '${fetch_prune:-<unset>}' (expected 'true')"
  status=1
else
  echo "✅ fetch.prune is configured"
fi

if [[ "${pull_ff}" != "only" ]]; then
  echo "❌ pull.ff is '${pull_ff:-<unset>}' (expected 'only')"
  status=1
else
  echo "✅ pull.ff is configured"
fi

if [[ ! -x ".githooks/pre-commit" ]]; then
  echo "❌ .githooks/pre-commit is missing or not executable"
  status=1
else
  echo "✅ .githooks/pre-commit exists and is executable"
fi

exit ${status}
