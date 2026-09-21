#!/bin/bash
# Guard Dog Nightly Cron Scanner
# Scans all package.json files in the workspace
#
# Legacy/manual wrapper. The supported scheduler command is:
#   myos-guard-dog updates enable --workspace "/your/workspace" --time 02:30
#
# Change WORKSPACE below to the directory you want to scan.

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${GUARDOG_WORKSPACE:-$HOME}"
LOG_DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "===== Guard Dog Nightly Scan: $LOG_DATE ====="

# Dead-man switch for spending reconciliation. It sends an alert when Scrooge
# has not written a valid reconciliation state for 26 hours, then scan proceeds.
node "$GUARD_DOG_DIR/bin/check-scrooge-freshness.cjs" || true

# Dead-man switch for the daily Stripe/Gumroad revenue pull (Revenue Pulse).
# Redundant with its own 8:30am check; this catches the case where that job
# itself failed to fire.
node "$HOME/.myos/workspace/agents/revenue-pulse/bin/check-revenue-pulse-freshness.cjs" || true

# Delegate dependency discovery and stopping conditions to the released nightly
# runner. It uses the cross-process VirusTotal daily budget and stops the run as
# soon as that budget is exhausted, unlike the historical per-manifest loop.
GUARDOG_WORKSPACE="$WORKSPACE" node "$GUARD_DOG_DIR/bin/nightly-scan.js"
