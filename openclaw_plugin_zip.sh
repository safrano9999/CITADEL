#!/usr/bin/env bash
set -euo pipefail

repo="$(basename "$PWD")"
zip_name="${ZIP_NAME:-$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')-latest.zip}"
archive_list="${ARCHIVE_LIST:-/tmp/openclaw-plugin-archive-files.txt}"
dev_only_re='(^|/)tag\.sh$'
candidate_list="$(mktemp)"
include_list="$(mktemp)"
ignored_list="$(mktemp)"
leak_list="$(mktemp)"
trap 'rm -f "$candidate_list" "$include_list" "$ignored_list" "$leak_list"' EXIT

case "$repo" in
  DAILYNEWS) files=(README.md config.json openclaw.plugin.json package.json requirements.txt index.js generate.py scripts skills) ;;
  CALENDAR) files=(README.md calendar_fetch.py config.json openclaw.plugin.json package.json requirements.txt index.js scripts) ;;
  ZEROINBOX) files=(README.md provider.conf openclaw.plugin.json package.json requirements.txt index.js scripts skills zeroinbox) ;;
  CITADEL) files=(README.md CITADEL_CLOUDFLARE.md CITADEL.png citadel.svg config.ini.example openclaw.plugin.json package.json requirements.txt index.js scan.sh set_daemon.sh webui.py assets extensions functions skills templates tests) ;;
  KACHELMANN) files=(README.md config.json openclaw.plugin.json package.json requirements.txt requirements-mysql.txt requirements-postgres.txt index.js scripts systemd kachelmann static templates webui.py) ;;
  SPANKER) files=(README.md assets openclaw.plugin.json package.json requirements.txt index.js scripts systemd spanker) ;;
  *) echo "Unsupported OpenClaw plugin repo: $repo" >&2; exit 2 ;;
esac

rm -f "$zip_name" "$zip_name.sha256"
for path in "${files[@]}"; do
  [ -e "$path" ] || continue
  if [ -d "$path" ]; then
    find "$path" -type f | sort
  else
    printf '%s\n' "$path"
  fi
done | grep -Ev "$dev_only_re" > "$candidate_list"
for optional in config.sh python_header.py sqlite_persistence.sh env.example config.conf_example container.example; do
  [ -f "$optional" ] && printf '%s\n' "$optional" >> "$candidate_list"
done
git check-ignore --no-index --stdin < "$candidate_list" > "$ignored_list" || true
grep -vxF -f "$ignored_list" "$candidate_list" > "$include_list"
zip -q "$zip_name" -@ < "$include_list"
sha256sum "$zip_name" > "$zip_name.sha256"
zipinfo -1 "$zip_name" | tee "$archive_list"
if grep -E "$dev_only_re" "$archive_list" > "$leak_list"; then
  cat "$leak_list"
  echo "Refusing to publish archive with dev-only files." >&2
  exit 1
fi
git check-ignore --no-index --stdin < "$archive_list" > "$leak_list" || true
if [ -s "$leak_list" ]; then
  cat "$leak_list"
  echo "Refusing to publish archive with files ignored by .gitignore." >&2
  exit 1
fi
