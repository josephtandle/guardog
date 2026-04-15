#!/usr/bin/env bash
# Run gstack /gstack-cso security review on a target path
# Usage: bin/run-cso.sh <path>
# Called manually or after a BARK/WHINE result from guard-dog

set -euo pipefail

TARGET="${1:-.}"

if ! command -v claude &>/dev/null; then
  echo "claude CLI not found, install Claude Code to use /gstack-cso"
  exit 1
fi

# If TARGET is a file, cd to its parent directory; otherwise cd into it
if [ -f "$TARGET" ]; then
  CWD=$(dirname "$TARGET")
elif [ -d "$TARGET" ]; then
  CWD="$TARGET"
else
  echo "Target not found: $TARGET"
  exit 1
fi

echo "Running /gstack-cso security review on: $TARGET (cwd: $CWD)"
cd "$CWD" && claude --print "/gstack-cso"
