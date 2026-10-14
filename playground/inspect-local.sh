#!/usr/bin/env bash
# Trusted local host only. Never upload .local or credentials to source/Issues.
set -euo pipefail
task_account_id="${1:?Usage: bash playground/inspect-local.sh CLOUDFLARE_ACCOUNT_ID}"
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
umask 077
mkdir -p .local
task_output="$(mktemp .local/inspection.XXXXXX)"
trap 'unset VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN; rm -f -- "$task_output"' EXIT

cargo build --locked
if [[ -z "${VALUEDOMAIN_ACCESS_TOKEN:-}" ]]; then
  read -rsp 'ValueDomain v2 access token: ' VALUEDOMAIN_ACCESS_TOKEN
  echo
fi
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  read -rsp 'Cloudflare API token: ' CLOUDFLARE_API_TOKEN
  echo
fi
export VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN

task_status=0
target/debug/zixcel-domain inspect "$task_account_id" > "$task_output" || task_status=$?
if [[ "$task_status" == 0 || "$task_status" == 2 ]]; then
  mv -- "$task_output" .local/inspection.json
  rm -f -- .local/inspection-error.json
  echo "Read-only NS/DNS observations saved to .local/inspection.json (status=$task_status; 2 means incomplete)"
  exit "$task_status"
else
  cat -- "$task_output"
  mv -- "$task_output" .local/inspection-error.json
  exit 1
fi
