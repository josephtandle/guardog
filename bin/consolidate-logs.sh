#!/bin/bash
# Consolidate and archive logs monthly

GUARD_DOG_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONTH=$(date +%Y-%m)
ARCHIVE_DIR="$GUARD_DOG_HOME/archive/$(date +%Y)/$MONTH"

mkdir -p "$ARCHIVE_DIR"

# Compress and archive monthly logs
tar -czf "$ARCHIVE_DIR/logs-$MONTH.tar.gz" \
  "$GUARD_DOG_HOME/logs/" \
  "$GUARD_DOG_HOME/reports/"

# Create monthly index
jq -s . "$GUARD_DOG_HOME/logs"/*/*.json > "$ARCHIVE_DIR/month-index.json" 2>/dev/null

echo "Archived logs for $MONTH to $ARCHIVE_DIR"
