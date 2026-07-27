#!/usr/bin/env bash
set -euo pipefail

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

while :; do
  ids="$(
    gh api "/repos/${repo}/actions/artifacts?per_page=100" \
      --jq '.artifacts[].id'
  )"
  [ -n "$ids" ] || break

  while IFS= read -r artifact_id; do
    [ -n "$artifact_id" ] || continue
    gh api -X DELETE "/repos/${repo}/actions/artifacts/${artifact_id}" >/dev/null
  done <<< "$ids"
done

echo "Actions artifacts remaining: $(gh api "/repos/${repo}/actions/artifacts?per_page=1" --jq '.total_count')"
