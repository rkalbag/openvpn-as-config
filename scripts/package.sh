#!/usr/bin/env bash
# Write dist/as-config-<version>.zip from the files git tracks, and nothing else.
# Working files (out/, tests/tmp/, data/, backups/, dist/) are excluded even if someone
# force-adds them to git, because they can hold server secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "package.sh: not a git repository; run 'git init' and 'git add' the files to ship first" >&2
  exit 1
fi
VERSION=$(python3 as_config.py --version | awk '{print $2}')
OUT="dist/as-config-$VERSION.zip"

FILES=()
while IFS= read -r -d '' f; do
  case "$f" in
    out/*|tests/tmp/*|data/*|backups/*|dist/*) echo "package.sh: skipping working file $f" >&2; continue ;;
  esac
  # A tracked symlink could pull any file on this machine (an SSH key, say) into the archive.
  [ -L "$f" ] && { echo "package.sh: $f is a symlink; refusing to package it" >&2; exit 1; }
  [ -f "$f" ] || { echo "package.sh: $f is tracked but missing from the working tree" >&2; exit 1; }
  FILES+=("$f")
done < <(git ls-files -z)
[ ${#FILES[@]} -gt 0 ] || { echo "package.sh: git tracks no files" >&2; exit 1; }

mkdir -p dist
rm -f "$OUT"
python3 - "$OUT" "as-config-$VERSION" "${FILES[@]}" <<'PY'
import os, sys, zipfile
out, prefix, files = sys.argv[1], sys.argv[2], sys.argv[3:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(files):
        info = zipfile.ZipInfo.from_file(f, f"{prefix}/{f}")
        info.date_time = (2026, 1, 1, 0, 0, 0)       # stable archive for the same files
        with open(f, "rb") as fh:
            z.writestr(info, fh.read(), zipfile.ZIP_DEFLATED)
PY
echo "$OUT (${#FILES[@]} files)"
