#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
task_binary="${ZIXCEL_DOMAIN_BIN:-${HOME}/.local/bin/zixcel-domain}"
if [[ ! -x "$task_binary" ]]; then
  echo 'Install the released zixcel-domain binary first.' >&2
  exit 1
fi
umask 077
mkdir -p .local
task_output="$(mktemp .local/valuedomain-domains.XXXXXX)"
trap 'unset VALUEDOMAIN_ACCESS_TOKEN; rm -f -- "$task_output"' EXIT
if [[ -z "${VALUEDOMAIN_ACCESS_TOKEN:-}" ]]; then
  read -rsp 'ValueDomain v2 access token: ' VALUEDOMAIN_ACCESS_TOKEN
  echo
fi
export VALUEDOMAIN_ACCESS_TOKEN
if "$task_binary" valuedomain-domains > "$task_output"; then
  mv -- "$task_output" .local/valuedomain-domains.json
  rm -f -- .local/valuedomain-domains-error.json
  echo 'Domain list saved to .local/valuedomain-domains.json'
else
  cat -- "$task_output"
  mv -- "$task_output" .local/valuedomain-domains-error.json
  exit 1
fi
