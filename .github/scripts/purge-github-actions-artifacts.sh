#!/usr/bin/env bash
# Source of truth: SCRIPTS/githubactions. Generated copies are overwritten.
set -euo pipefail

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
command -v gh >/dev/null 2>&1 || {
  echo "gh is required" >&2
  exit 1
}

ids="$(
  gh api --paginate "/repos/${repo}/actions/artifacts?per_page=100" \
    --jq '.artifacts[].id'
)"

while IFS= read -r artifact_id; do
  [ -n "$artifact_id" ] || continue
  if ! gh api -X DELETE "/repos/${repo}/actions/artifacts/${artifact_id}" >/dev/null; then
    echo "WARNING: could not delete Actions artifact $artifact_id" >&2
  fi
done <<< "$ids"

echo "Actions artifacts remaining: $(gh api "/repos/${repo}/actions/artifacts?per_page=1" --jq '.total_count')"
