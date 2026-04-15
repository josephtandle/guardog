#!/bin/bash
# Guard Dog Threat Intelligence Daily Scanner
# Runs the Node.js threat intel scanner with proper environment
#
# LaunchAgent: ai.openclaw.guard-dog-threat-intel (3:00 AM daily)

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$GUARD_DOG_DIR/data/threat-intel.log"
LOG_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Ensure data dir exists
mkdir -p "$GUARD_DOG_DIR/data"

echo "" >> "$LOG_FILE"
echo "===== Threat Intel Scan: $LOG_DATE =====" >> "$LOG_FILE"

# Run the Node.js scanner
node "$GUARD_DOG_DIR/bin/threat-intel-daily.js" >> "$LOG_FILE" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "===== Scan completed successfully =====" >> "$LOG_FILE"
  # Sync findings to vulnerability database for MC tracking
  echo "Syncing vulnerabilities to database..." >> "$LOG_FILE"
  node "$GUARD_DOG_DIR/bin/sync-vulns-to-db.js" >> "$LOG_FILE" 2>&1
  echo "Vulnerability DB sync complete" >> "$LOG_FILE"
else
  echo "===== Scan failed with exit code $EXIT_CODE =====" >> "$LOG_FILE"
fi

# Trim log to last 5000 lines to prevent unbounded growth
if [ -f "$LOG_FILE" ]; then
  LINES=$(wc -l < "$LOG_FILE")
  if [ "$LINES" -gt 5000 ]; then
    tail -n 5000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
  fi
fi

exit $EXIT_CODE
