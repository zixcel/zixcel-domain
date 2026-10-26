#!/usr/bin/env bash
# Install an official immutable native release; never build source as fallback.
set -euo pipefail
umask 077
version=${1:?Usage: install-native-local.sh VERSION}
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || exit 2
command -v zix >/dev/null
command -v gh >/dev/null
python3 - <<'PY_VERSION'
import re,subprocess
value=subprocess.check_output(['zix','version'],text=True).strip()
m=re.fullmatch(r'zix (\d+)\.(\d+)\.(\d+)',value)
if not m or tuple(map(int,m.groups())) < (0,2,5):
    raise SystemExit('zix >=0.2.5 is required before replacing the Domain extension')
PY_VERSION
base_dir="${XDG_DATA_HOME:-$HOME/.local/share}/zix/packages"
install -d -m 700 "$base_dir"
package_dir=$(mktemp -d "$base_dir/domain-$version.XXXXXXXX")
archive="zixcel-domain-cli-v$version-x86_64-unknown-linux-musl.tar.gz"
gh release download "native/domain/v$version" --repo zixcel/zixcel-domain --pattern "$archive" --pattern SHA256SUMS --dir "$package_dir"
(
  cd "$package_dir"
  # Check exactly the expected archive. Do not execute filenames from a checksum file.
  test "$(wc -l < SHA256SUMS)" -eq 1
  read -r digest filename < SHA256SUMS
  [[ "$digest" =~ ^[a-f0-9]{64}$ && "$filename" == "$archive" ]]
  printf '%s  %s\n' "$digest" "$archive" | sha256sum --check
  # Inspect archive membership before extraction, including link types.
  python3 - "$archive" <<'PY'
import sys,tarfile
with tarfile.open(sys.argv[1]) as t:
    names=set()
    for m in t:
        from pathlib import PurePosixPath
        p=PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir()) or m.name in names:
            raise SystemExit('unsafe release archive')
        names.add(m.name)
PY
  tar --no-same-owner -xzf "$archive"
)
mapfile -t manifests < <(find "$package_dir" -name domain.extension.json -type f)
test "${#manifests[@]}" -eq 1
manifest=${manifests[0]}
executable="$(dirname "$manifest")/zix-domain"
(
  cd "$(dirname "$manifest")"
  sha256sum --check CONTENTS.sha256
  ./zix-domain --manifest > observed-manifest.json
  cmp domain.extension.json observed-manifest.json
  python3 - "$version" <<'PY_MANIFEST'
import json,sys
m=json.load(open('domain.extension.json'))
if (m['namespace'],m['version'],m['platform']) != ('domain',sys.argv[1],'linux-x86_64') or m['schema'] not in ('zix-extension/v1','zix-extension/v2'):
    raise SystemExit('unexpected Domain release identity')
PY_MANIFEST
)
# Metadata lookup includes disabled registrations. Any read/parse error stops here.
zix extensions list --format json > "$package_dir/previous-registrations.json"
python3 - "$package_dir/previous-registrations.json" > "$package_dir/previous-hashes.txt" <<'PY_STATE'
import json,sys
inventory=json.load(open(sys.argv[1]))
for entry in inventory['entries']:
    if entry['namespace']=='domain':
        print(entry['manifest_sha256'])
        print(entry['executable_sha256'])
PY_STATE
mapfile -t previous < "$package_dir/previous-hashes.txt"
args=(--manifest "$manifest" --manifest-sha256 "$(sha256sum "$manifest" | cut -d' ' -f1)"
      --executable "$executable" --executable-sha256 "$(sha256sum "$executable" | cut -d' ' -f1)")
if [[ ${#previous[@]} == 2 ]]; then
  zix extensions replace "${args[@]}" --expected-manifest-sha256 "${previous[0]}" --expected-executable-sha256 "${previous[1]}"
elif [[ ${#previous[@]} == 0 ]]; then
  zix extensions add "${args[@]}"
else
  echo 'Invalid registration metadata; no changes performed.' >&2
  exit 2
fi
zix extensions inspect domain --format json
