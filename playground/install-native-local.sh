#!/usr/bin/env bash
# Install an official immutable native release; never build source as fallback.
set -euo pipefail
umask 077
version=${1:?Usage: install-native-local.sh VERSION}
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || exit 2
command -v zix >/dev/null
command -v gh >/dev/null
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
)
# Save enough registration evidence to restore the previous verified package if needed.
zix describe domain --format json > "$package_dir/previous-manifest.json" 2> "$package_dir/previous-error.json" && installed=true || installed=false
registry="${XDG_CONFIG_HOME:-$HOME/.config}/zix/extensions.json"
if [[ -f "$registry" ]]; then cp -- "$registry" "$package_dir/previous-extensions.json"; fi
if "$installed"; then zix extensions remove domain; fi
if ! zix extensions add --manifest "$manifest" --manifest-sha256 "$(sha256sum "$manifest" | cut -d' ' -f1)" --executable "$executable" --executable-sha256 "$(sha256sum "$executable" | cut -d' ' -f1)"; then
  if "$installed"; then
    python3 - "$package_dir/previous-extensions.json" "$package_dir" <<'PY_RESTORE'
import json,pathlib,subprocess,sys
previous=json.load(open(sys.argv[1]))
entry=next(e for e in previous['entries'] if json.loads(e['manifest_text'])['namespace']=='domain')
manifest=pathlib.Path(sys.argv[2])/'restore-manifest.json'
manifest.write_text(entry['manifest_text'])
subprocess.run(['zix','extensions','add','--manifest',str(manifest),'--manifest-sha256',entry['manifest_sha256'],'--executable',entry['executable'],'--executable-sha256',entry['executable_sha256']],check=True)
if not entry['enabled']:
    subprocess.run(['zix','extensions','disable','domain'],check=True)
PY_RESTORE
  fi
  exit 2
fi
zix describe domain --format json
