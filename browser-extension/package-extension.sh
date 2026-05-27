#!/usr/bin/env bash
#
# package-extension.sh
#
# Builds a clean Chrome Web Store upload ZIP for the ConfigTrace browser
# extension prototype.
#
# Output:
#   dist/configtrace-provider-console-helper-<VERSION>.zip
#
# Behaviour:
#   • Read VERSION from manifest.json (so the script and the manifest never
#     drift apart).
#   • Always work from this script's own directory; never depend on cwd.
#   • Re-create dist/ fresh on every run.
#   • Build the ZIP by listing the exact files we want (allow-list, not
#     deny-list) — this is the safest defence against accidentally
#     shipping .git, .DS_Store, screenshots, dev docs, or env files.
#   • Print the resulting path + size, plus a manifest of the ZIP contents.
#
# This script does NOT submit the ZIP. The maintainer uploads it manually
# in the Chrome Web Store Developer Dashboard.

set -euo pipefail

# Resolve directory of this script (works from any cwd, handles symlinks)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# ── Sanity checks ─────────────────────────────────────────────────────
if [[ ! -f manifest.json ]]; then
  echo "[package] ERROR: manifest.json not found in $SCRIPT_DIR" >&2
  exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
  echo "[package] ERROR: 'zip' command not found in PATH" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[package] ERROR: 'python3' is required to read the manifest version" >&2
  exit 1
fi

# Validate manifest.json parses, and read the version.
if ! python3 -c "import json,sys; json.load(open('manifest.json'))" 2>/dev/null; then
  echo "[package] ERROR: manifest.json is not valid JSON" >&2
  exit 1
fi
VERSION="$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])")"
if [[ -z "$VERSION" ]]; then
  echo "[package] ERROR: could not read 'version' from manifest.json" >&2
  exit 1
fi

# ── Output paths ──────────────────────────────────────────────────────
DIST_DIR="$SCRIPT_DIR/dist"
ZIP_NAME="configtrace-provider-console-helper-${VERSION}.zip"
ZIP_PATH="$DIST_DIR/$ZIP_NAME"

echo "[package] working dir : $SCRIPT_DIR"
echo "[package] version     : $VERSION"
echo "[package] target zip  : $ZIP_PATH"

# ── Fresh dist/ ───────────────────────────────────────────────────────
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# ── Allow-list of files/directories to ship ───────────────────────────
#
# This is intentional: a deny-list could miss a future stray file
# (e.g. a hidden editor backup) that we wouldn't want to ship.
INCLUDES=(
  "manifest.json"
  "README.md"
  "src/background.js"
  "src/contentScript.js"
  "src/guidance.js"
  "src/popup.html"
  "src/popup.js"
  "src/popup.css"
  "icons/icon.svg"
  "icons/icon16.png"
  "icons/icon32.png"
  "icons/icon48.png"
  "icons/icon128.png"
)

# Verify every entry exists before we zip
MISSING=()
for f in "${INCLUDES[@]}"; do
  if [[ ! -e "$f" ]]; then
    MISSING+=("$f")
  fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "[package] ERROR: missing files required for packaging:" >&2
  for f in "${MISSING[@]}"; do echo "    - $f" >&2; done
  exit 1
fi

# Explicit excludes — applied even though we use an allow-list, as belt-
# and-suspenders against editor temp files or .DS_Store inside `icons/`.
EXCLUDES=(
  "*.DS_Store"
  "**/.DS_Store"
  "*.bak"
  "*~"
  "*.swp"
  ".env"
  ".env.*"
)

# ── Build the ZIP ─────────────────────────────────────────────────────
EXCLUDE_ARGS=()
for pat in "${EXCLUDES[@]}"; do
  EXCLUDE_ARGS+=("-x" "$pat")
done

# -r recurse  -q quiet  -X strip extra macOS attrs  -9 best compression
zip -r -q -X -9 "$ZIP_PATH" "${INCLUDES[@]}" "${EXCLUDE_ARGS[@]}"

# ── Report ────────────────────────────────────────────────────────────
SIZE_HUMAN="$(du -h "$ZIP_PATH" | awk '{print $1}')"
SIZE_BYTES="$(stat -f%z "$ZIP_PATH" 2>/dev/null || stat -c%s "$ZIP_PATH")"

echo ""
echo "[package] built: $ZIP_PATH"
echo "[package] size : ${SIZE_HUMAN} (${SIZE_BYTES} bytes)"
echo ""
echo "[package] contents:"
unzip -l "$ZIP_PATH" | sed 's/^/    /'

# ── Forbidden-path audit ──────────────────────────────────────────────
echo ""
echo "[package] forbidden-path audit (should print nothing):"
FORBIDDEN_HITS="$(unzip -l "$ZIP_PATH" | awk 'NR>3 {print $4}' \
  | grep -E '^(\.git/|\.git$|node_modules/|dist/|\.DS_Store$|^\.env|screenshots/|store-listing\.md|privacy-disclosure\.md|package-extension\.sh|icons/generate_icons\.py)' \
  || true)"
if [[ -n "$FORBIDDEN_HITS" ]]; then
  echo "[package] ERROR: ZIP contains forbidden paths:" >&2
  echo "$FORBIDDEN_HITS" | sed 's/^/    /' >&2
  exit 1
else
  echo "    (clean)"
fi

echo ""
echo "[package] done. Upload manually via Chrome Web Store Developer Dashboard:"
echo "    https://chrome.google.com/webstore/devconsole"
