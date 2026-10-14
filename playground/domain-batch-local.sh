#!/usr/bin/env bash
# Selected domains only; credentials are inherited by scoped sessions, never saved.
set -euo pipefail
task_account="${1:?Usage: domain-batch-local.sh ACCOUNT [--allow-empty-registered-unserved] DOMAIN...}"
shift
task_policy=''
task_retire_domains=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-empty-registered-unserved) task_policy="$1"; shift ;;
    --retire-unused-mail=*) IFS=',' read -r -a task_retire_domains <<< "${1#*=}"; shift ;;
    *) break ;;
  esac
done
[[ "$task_account" =~ ^[a-f0-9]{32}$ && $# -gt 0 && $# -le 20 ]] || exit 2
for task_domain in "$@"; do [[ "$task_domain" =~ ^[a-z0-9.-]+$ && ${#task_domain} -le 253 ]] || exit 2; done
for task_retire in "${task_retire_domains[@]}"; do
  task_found=false
  for task_domain in "$@"; do [[ "$task_retire" == "$task_domain" ]] && task_found=true; done
  [[ "$task_found" == true ]] || exit 2
done
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
task_binary="${ZIXCEL_DOMAIN_BIN:-${HOME}/.local/bin/zixcel-domain}"
umask 077
mkdir -p .local
chmod 700 .local
trap 'unset VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN' EXIT
read -rsp 'ValueDomain v2 access token: ' VALUEDOMAIN_ACCESS_TOKEN
printf '\n'
read -rsp 'Cloudflare API token: ' CLOUDFLARE_API_TOKEN
printf '\n'
export VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN
for task_domain in "$@"; do
  printf 'Selected domain: %s\n' "$task_domain"
  task_arguments=(domain-session .local/domain-control.sock "$task_domain" "$task_account")
  if [[ -n "$task_policy" ]]; then task_arguments+=("$task_policy"); fi
  for task_retire in "${task_retire_domains[@]}"; do
    if [[ "$task_retire" == "$task_domain" ]]; then task_arguments+=(--retire-unused-mail); fi
  done
  task_result="$("$task_binary" "${task_arguments[@]}")"
  printf '%s' "$task_result" | python3 -c 'import json,sys; value=json.load(sys.stdin); assert value.get("result",{}).get("session_closed")=="requested", "session expired/failed; batch stopped without advancing"'
done
