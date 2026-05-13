#!/usr/bin/env bash
# Run gstack /gstack-cso security review on a target path
# Usage: bin/run-cso.sh <path>
# Called manually or after a BARK/WHINE result from guard-dog

set -euo pipefail

TARGET="${1:-.}"

echo "Claude Code /gstack-cso runner is disabled after Anthropic cleanup."
exit 1
