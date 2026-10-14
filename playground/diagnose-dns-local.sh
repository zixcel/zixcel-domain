#!/usr/bin/env bash
# Read-only comparison of registered-domain DNS and FreeDNS; credentials stay local.
set -euo pipefail
task_domain="${1:?Usage: diagnose-dns-local.sh DOMAIN}"
[[ "$task_domain" =~ ^[a-zA-Z0-9.-]+$ && ${#task_domain} -le 253 ]] || exit 1
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
task_binary="${ZIXCEL_DOMAIN_BIN:-${HOME}/.local/bin/zixcel-domain}"
umask 077
mkdir -p .local
chmod 700 .local
task_directory="$(mktemp -d .local/dns-diagnosis.XXXXXX)"
trap 'unset VALUEDOMAIN_ACCESS_TOKEN' EXIT
if [[ -z "${VALUEDOMAIN_ACCESS_TOKEN:-}" ]]; then
  read -rsp 'ValueDomain v2 access token: ' VALUEDOMAIN_ACCESS_TOKEN
  echo
fi
export VALUEDOMAIN_ACCESS_TOKEN
for task_operation in valuedomain-settings valuedomain-free-dns public-nameservers; do
  task_status=0
  "$task_binary" "$task_operation" "$task_domain" > "$task_directory/$task_operation.json" || task_status=$?
  printf '%s\n' "$task_status" > "$task_directory/$task_operation.status"
done
python3 - "$task_directory" "$task_domain" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
summary = {'domain': sys.argv[2], 'writes_performed': False, 'operations': {}}
for name in ['valuedomain-settings', 'valuedomain-free-dns', 'public-nameservers']:
    response = json.loads((root / (name + '.json')).read_text())
    if 'error' in response:
        summary['operations'][name] = {'error': response['error']}
        continue
    value = response['result']
    safe = {k: value[k] for k in ['domain', 'nameservers', 'stored_dns_type', 'stored_dns_ttl', 'ns_type', 'ttl'] if k in value}
    records = value.get('stored_dns_records', value.get('records'))
    if isinstance(records, str): safe['record_lines'] = len(records.splitlines())
    summary['operations'][name] = safe
summary['private_observations'] = str(root.resolve())
pathlib.Path('.local/dns-diagnosis.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
PY
