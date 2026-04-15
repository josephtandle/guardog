#!/bin/bash
# Guard Dog Git Pre-Commit Hook
# Scans new/changed dependencies when package.json is modified.
#
# Install in a repo:
#   cp ~/guardog/bin/git-precommit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or install globally (install.sh does this automatically):
#   git config --global core.hooksPath ~/guardog/bin/hooks

GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Check if package.json is staged
STAGED_PKG=$(git diff --cached --name-only | grep -E '^(.*\/)?package\.json$')

if [ -z "$STAGED_PKG" ]; then
  # No package.json changes, skip scan
  exit 0
fi

echo "🐕 Guard Dog: package.json changes detected, scanning new dependencies..."

for PKG_FILE in $STAGED_PKG; do
  if [ ! -f "$PKG_FILE" ]; then
    continue
  fi

  # Get the old version from HEAD for comparison
  OLD_TMP=$(mktemp)
  git show HEAD:"$PKG_FILE" > "$OLD_TMP" 2>/dev/null

  if [ -s "$OLD_TMP" ]; then
    # Compare old vs new — only scan changed deps
    node "$GUARD_DOG_DIR/bin/scan-deps.js" "$PKG_FILE" --changed-only "$OLD_TMP" 2>&1
  else
    # New package.json — scan everything
    node "$GUARD_DOG_DIR/bin/scan-deps.js" "$PKG_FILE" 2>&1
  fi

  EXIT_CODE=$?
  rm -f "$OLD_TMP"

  if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "🚨 Guard Dog BLOCKED commit: dangerous dependencies found in $PKG_FILE"
    echo "   Review the output above and remove dangerous packages before committing."
    exit 1
  fi
done

echo "✅ Guard Dog: All dependencies clear."
exit 0
