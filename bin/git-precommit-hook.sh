#!/bin/bash
# MyOS Guard Dog Git pre-commit hook.
# Audits staged dependency changes. Non-dependency manifest edits do not pay for
# a full network audit, while changed dependencies remain fail-closed.

GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GUARD_DOG_NODE:-node}"

has_workspaces() {
  "$NODE_BIN" -e '
    const fs = require("node:fs");
    const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.exit(manifest.workspaces == null ? 1 : 0);
  ' "$1"
}

CHANGED_LIST=$(mktemp)
CANDIDATES=$(mktemp)
trap 'rm -f "$CHANGED_LIST" "$CANDIDATES"' EXIT
git diff --cached --name-only -z --diff-filter=ACMR -- '*package.json' '*package-lock.json' '*npm-shrinkwrap.json' > "$CHANGED_LIST"

if [ ! -s "$CHANGED_LIST" ]; then
  exit 0
fi

while IFS= read -r -d '' CHANGED_FILE; do
  case "$(basename "$CHANGED_FILE")" in
    package.json) PKG_FILE="$CHANGED_FILE" ;;
    package-lock.json|npm-shrinkwrap.json) PKG_FILE="$(dirname "$CHANGED_FILE")/package.json" ;;
    *) continue ;;
  esac
  PKG_FILE="${PKG_FILE#./}"
  if git cat-file -e ":$PKG_FILE" 2>/dev/null; then
    printf '%s\0%s\0' "$CHANGED_FILE" "$PKG_FILE" >> "$CANDIDATES"
  fi
done < "$CHANGED_LIST"

if [ ! -s "$CANDIDATES" ]; then
  exit 0
fi

echo "🐕 MyOS Guard Dog: staged dependency metadata changes detected."

while IFS= read -r -d '' CHANGED_FILE && IFS= read -r -d '' PKG_FILE; do
  STAGED_DIR=$(mktemp -d)
  OLD_TMP=$(mktemp)
  trap 'rm -f "$CHANGED_LIST" "$CANDIDATES" "$OLD_TMP"; rm -rf "$STAGED_DIR"' EXIT

  if ! git show ":$PKG_FILE" > "$STAGED_DIR/package.json"; then
    echo "MyOS Guard Dog could not read staged $PKG_FILE."
    exit 1
  fi
  git show "HEAD:$PKG_FILE" > "$OLD_TMP" 2>/dev/null || printf '{}\n' > "$OLD_TMP"

  WORKSPACE_ROOT=""
  if has_workspaces "$STAGED_DIR/package.json"; then
    WORKSPACE_ROOT="$PKG_FILE"
  else
    SEARCH_DIR=$(dirname "$PKG_FILE")
    while [ "$SEARCH_DIR" != "." ]; do
      SEARCH_DIR=$(dirname "$SEARCH_DIR")
      if [ "$SEARCH_DIR" = "." ]; then ANCESTOR_MANIFEST="package.json"; else ANCESTOR_MANIFEST="$SEARCH_DIR/package.json"; fi
      ANCESTOR_TMP=$(mktemp)
      if git show ":$ANCESTOR_MANIFEST" > "$ANCESTOR_TMP" 2>/dev/null && has_workspaces "$ANCESTOR_TMP"; then
        WORKSPACE_ROOT="$ANCESTOR_MANIFEST"
        rm -f "$ANCESTOR_TMP"
        break
      fi
      rm -f "$ANCESTOR_TMP"
    done
  fi
  if [ -n "$WORKSPACE_ROOT" ]; then
    echo "MyOS Guard Dog BLOCKED commit: npm workspace inventory is not yet supported for $PKG_FILE (workspace root: $WORKSPACE_ROOT)."
    echo "Audit the staged workspace and root lockfile with workspace-aware tooling before committing."
    exit 1
  fi

  if [ "$(basename "$CHANGED_FILE")" = "package.json" ] && "$NODE_BIN" -e '
    const fs = require("node:fs");
    const { isDeepStrictEqual } = require("node:util");
    const fields = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "bundleDependencies", "overrides", "resolutions", "workspaces"];
    const read = file => JSON.parse(fs.readFileSync(file, "utf8"));
    const pick = value => Object.fromEntries(fields.map(field => [field, value[field] ?? null]));
    process.exit(isDeepStrictEqual(pick(read(process.argv[1])), pick(read(process.argv[2]))) ? 0 : 1);
  ' "$OLD_TMP" "$STAGED_DIR/package.json"; then
    echo "MyOS Guard Dog: dependency resolution metadata is unchanged in $PKG_FILE; no dependency audit needed."
    rm -f "$OLD_TMP"
    rm -rf "$STAGED_DIR"
    trap 'rm -f "$CHANGED_LIST" "$CANDIDATES"' EXIT
    continue
  fi

  PKG_DIR=$(dirname "$PKG_FILE")
  for LOCK_NAME in npm-shrinkwrap.json package-lock.json; do
    if [ "$PKG_DIR" = "." ]; then LOCK_PATH="$LOCK_NAME"; else LOCK_PATH="$PKG_DIR/$LOCK_NAME"; fi
    git show ":$LOCK_PATH" > "$STAGED_DIR/$LOCK_NAME" 2>/dev/null || true
  done

  "$NODE_BIN" "$GUARD_DOG_DIR/bin/scan-deps.js" "$STAGED_DIR/package.json" 2>&1
  EXIT_CODE=$?
  rm -f "$OLD_TMP"
  rm -rf "$STAGED_DIR"
  trap 'rm -f "$CHANGED_LIST" "$CANDIDATES"' EXIT

  if [ "$EXIT_CODE" -eq 1 ]; then
    echo ""
    echo "🚨 MyOS Guard Dog BLOCKED commit: confirmed dangerous dependencies found in $PKG_FILE"
    echo "   Review the findings above and remove the dangerous dependency before committing."
    exit 1
  fi
  if [ "$EXIT_CODE" -eq 2 ]; then
    echo ""
    echo "⚠️ MyOS Guard Dog BLOCKED commit: coverage is incomplete for changed dependencies in $PKG_FILE"
    echo "   Restore exact lockfile coverage and required security checks, then retry."
    exit 1
  fi
  if [ "$EXIT_CODE" -ne 0 ]; then
    echo "MyOS Guard Dog BLOCKED commit: dependency audit failed with exit code $EXIT_CODE."
    exit 1
  fi
done < "$CANDIDATES"

echo "✅ MyOS Guard Dog: staged dependency changes passed."
exit 0
