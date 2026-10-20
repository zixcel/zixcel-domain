#!/usr/bin/env bash
set -euo pipefail
config=.github/native-release.json
repository=$(jq -er '.repository' "$config")
package=$(jq -er '.package' "$config")
prefix=$(jq -er '.tag_prefix' "$config")
workflow=$(jq -er '.workflow' "$config")
test "${GITHUB_EVENT_NAME:-}" = push
test "${GITHUB_REF_TYPE:-}" = tag
test "${GITHUB_REPOSITORY:-}" = "$repository"
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]]
metadata=$(cargo metadata --locked --offline --no-deps --format-version 1)
version=$(jq -er --arg package "$package" '.packages | map(select(.name == $package)) | select(length == 1) | .[0].version' <<< "$metadata")
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
test "${GITHUB_REF_NAME:-}" = "$prefix$version"
test "${GITHUB_REF:-}" = "refs/tags/$prefix$version"
test "$(git rev-parse "$GITHUB_REF^{commit}")" = "$GITHUB_SHA"
git fetch --no-tags origin main
git merge-base --is-ancestor "$GITHUB_SHA" FETCH_HEAD
runs=$(gh api "repos/$repository/actions/workflows/$workflow/runs?branch=main&event=push&status=completed&head_sha=$GITHUB_SHA&per_page=100")
jq -e --arg sha "$GITHUB_SHA" --arg path ".github/workflows/$workflow" '
  (.total_count == (.workflow_runs | length)) and (.total_count < 100) and
  any(.workflow_runs[]; .head_sha == $sha and .head_branch == "main" and
      .event == "push" and .path == $path and .status == "completed" and .conclusion == "success")
' <<< "$runs" >/dev/null
printf 'Admitted owner %s source %s tag %s\n' "$repository" "$GITHUB_SHA" "$GITHUB_REF_NAME"
