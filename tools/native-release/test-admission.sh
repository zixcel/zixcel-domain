#!/usr/bin/env bash
set -euo pipefail
root=$(pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/.github"
cp .github/native-release.json "$fixture/.github/"
cat > "$fixture/bin/cargo" <<'SH'
#!/usr/bin/env bash
printf '{"packages":[{"name":"%s","version":"%s"}]}' "$TEST_PACKAGE" "${TEST_VERSION:-0.1.0}"
SH
cat > "$fixture/bin/git" <<'SH'
#!/usr/bin/env bash
case "$1" in
rev-parse) printf '%s' "${TEST_TAG_SHA:-$GITHUB_SHA}";;
fetch) exit 0;;
merge-base) test "${TEST_ANCESTOR:-yes}" = yes;;
*) exit 2;;
esac
SH
cat > "$fixture/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '{"total_count":%s,"workflow_runs":[{"head_sha":"%s","head_branch":"%s","event":"%s","path":".github/workflows/%s","status":"completed","conclusion":"%s"}]}' "${TEST_COUNT:-1}" "${TEST_RUN_SHA:-$GITHUB_SHA}" "${TEST_BRANCH:-main}" "${TEST_EVENT:-push}" "${TEST_WORKFLOW:-native-provider.yml}" "${TEST_CONCLUSION:-success}"
SH
chmod 700 "$fixture/bin/"*
export PATH="$fixture/bin:$PATH"
export TEST_PACKAGE=$(jq -r .package .github/native-release.json)
export GITHUB_REPOSITORY=$(jq -r .repository .github/native-release.json)
export GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export GITHUB_EVENT_NAME=push GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME="$(jq -r .tag_prefix .github/native-release.json)0.1.0"
export GITHUB_REF="refs/tags/$GITHUB_REF_NAME"
cd "$fixture"
check() { bash "$root/tools/native-release/admit.sh" >/dev/null 2>&1; }
reject() { if (export "$1"; check); then echo "Unexpected admission: $1" >&2; exit 1; fi; }
check
reject GITHUB_EVENT_NAME=pull_request
reject GITHUB_REF_TYPE=branch
reject GITHUB_REPOSITORY=example/other
reject GITHUB_SHA=invalid
reject TEST_VERSION=0.2.0
reject TEST_TAG_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
reject TEST_ANCESTOR=no
reject TEST_RUN_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
reject TEST_BRANCH=feature
reject TEST_EVENT=pull_request
reject TEST_WORKFLOW=unrelated.yml
reject TEST_CONCLUSION=failure
reject TEST_COUNT=100
printf '14 owner/version/source/CI admission scenarios passed. No network or writes.\n'
