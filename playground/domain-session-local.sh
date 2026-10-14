#!/usr/bin/env bash
set -euo pipefail
task_domain="${1:?Usage: domain-session-local.sh DOMAIN CLOUDFLARE_ACCOUNT_ID}"
task_account="${2:?Usage: domain-session-local.sh DOMAIN CLOUDFLARE_ACCOUNT_ID}"
task_policy="${3:-}"
if [[ -n "$task_policy" && "$task_policy" != '--allow-empty-registered-unserved' ]]; then exit 2; fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
task_binary="${ZIXCEL_DOMAIN_BIN:-${HOME}/.local/bin/zixcel-domain}"
umask 077
mkdir -p .local
chmod 700 .local
trap 'unset VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN' EXIT
if [[ -z "${VALUEDOMAIN_ACCESS_TOKEN:-}" ]]; then
  read -rsp 'ValueDomain v2 access token: ' VALUEDOMAIN_ACCESS_TOKEN
  echo
fi
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  read -rsp 'Cloudflare API token: ' CLOUDFLARE_API_TOKEN
  echo
fi
export VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN
task_arguments=(domain-session .local/domain-control.sock "$task_domain" "$task_account")
if [[ -n "$task_policy" ]]; then task_arguments+=("$task_policy"); fi
"$task_binary" "${task_arguments[@]}"
