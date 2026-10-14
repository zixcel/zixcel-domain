#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
task_binary="${ZIXCEL_DOMAIN_BIN:-${HOME}/.local/bin/zixcel-domain}"
if [[ ! -x "$task_binary" ]]; then
  echo 'Install the released zixcel-domain binary first.' >&2
  exit 1
fi
task_filename='valuedomain-domains'
if [[ $# -gt 0 ]]; then
  if [[ $# -ne 1 || "$1" != '--exclude-auto-renew-disabled' ]]; then
    echo 'Usage: list-domains-local.sh [--exclude-auto-renew-disabled]' >&2
    exit 1
  fi
  task_filename='valuedomain-domains-auto-renew'
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
if "$task_binary" valuedomain-domains "$@" > "$task_output"; then
  mv -- "$task_output" ".local/${task_filename}.json"
  rm -f -- ".local/${task_filename}-error.json"
  echo "Domain list saved to .local/${task_filename}.json"
else
  cat -- "$task_output"
  mv -- "$task_output" ".local/${task_filename}-error.json"
  exit 1
fi
