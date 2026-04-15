#!/bin/bash
# Guard Dog Nightly Cron Scanner
# Scans all package.json files in the workspace
#
# Cron entry (runs at 2:30 AM daily):
#   30 2 * * * ~/guardog/bin/cron-nightly-scan.sh >> ~/guardog/data/cron.log 2>&1
#
# Change WORKSPACE below to the directory you want to scan.

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${GUARDOG_WORKSPACE:-$HOME}"
LOG_DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "===== Guard Dog Nightly Scan: $LOG_DATE ====="

# Find all package.json files in workspace (skip node_modules)
PACKAGE_FILES=$(find "$WORKSPACE" -name "package.json" \
  -not -path "*/node_modules/*" \
  -not -path "*/.next/*" \
  -not -path "*/dist/*" \
  -not -path "*/build/*" \
  -maxdepth 4)

TOTAL=0
SCANNED=0
DANGEROUS=0

for PKG in $PACKAGE_FILES; do
  TOTAL=$((TOTAL + 1))
  PROJECT_DIR=$(dirname "$PKG")
  PROJECT_NAME=$(basename "$PROJECT_DIR")

  echo ""
  echo "--- Scanning: $PROJECT_NAME ($PKG) ---"

  node "$GUARD_DOG_DIR/bin/scan-deps.js" "$PKG" 2>&1
  EXIT_CODE=$?
  SCANNED=$((SCANNED + 1))

  if [ $EXIT_CODE -ne 0 ]; then
    DANGEROUS=$((DANGEROUS + 1))
  fi
done

echo ""
echo "===== Nightly Scan Complete ====="
echo "Projects scanned: $SCANNED / $TOTAL"
echo "Dangerous projects: $DANGEROUS"
echo "================================="
