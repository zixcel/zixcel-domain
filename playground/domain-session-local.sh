#!/usr/bin/env bash
set -euo pipefail
task_domain="${1:?Usage: domain-session-local.sh DOMAIN CLOUDFLARE_ACCOUNT_ID}"
task_account="${2:?Usage: domain-session-local.sh DOMAIN CLOUDFLARE_ACCOUNT_ID}"
task_policies=("${@:3}")
for task_policy in "${task_policies[@]}"; do
  [[ "$task_policy" == '--allow-empty-registered-unserved' || "$task_policy" == '--retire-unused-mail' ]] || exit 2
done
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
task_arguments+=("${task_policies[@]}")
"$task_binary" "${task_arguments[@]}"
