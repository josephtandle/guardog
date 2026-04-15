# Guard Dog Security Operations Manifest

## Structure

```
guard-dog/
├── logs/                          # Real-time operational logs
│   ├── scans/                     # Vulnerability scan results
│   ├── alerts/                    # Security alerts triggered
│   ├── install-history/           # Package installation audit trail
│   └── dependency-tracking/       # Dependency update events
├── data/                          # Consolidated threat data
│   ├── vulnerabilities/           # Master vulnerability database
│   ├── remediation/               # Remediation tracking
│   └── baselines/                 # Security baselines
├── reports/                       # Generated reports
│   ├── daily/                     # Daily digests
│   ├── weekly/                    # Weekly summaries
│   ├── monthly/                   # Monthly reviews
│   └── critical-alerts/           # Critical incident reports
├── archive/                       # Historical records (compressed)
│   └── YYYY/MM/
└── bin/                           # Operational scripts
```

## Log Retention Policy

| Log Type | Retention | Format | Location |
|----------|-----------|--------|----------|
| Scans | 90 days | NDJSON | logs/scans/ |
| Alerts | 365 days | NDJSON | logs/alerts/ |
| Install History | 365 days | NDJSON | logs/install-history/ |
| Dependency Changes | 365 days | NDJSON | logs/dependency-tracking/ |
| Reports | 730 days | Markdown | reports/ |
| Critical Incidents | 1825 days | NDJSON | archive/ |

## Key Files

- `.logindex.json` - Log format and retention schema
- `logs/install-history/schema.json` - Installation audit structure
- `data/vulnerabilities/schema.json` - Vulnerability tracking format
- `MANIFEST.md` - This document

## Daily Operations

1. Scans run nightly (PATH-fixed cron)
2. Logs written to appropriate subdirectories
3. Daily digest generated at 06:30
4. Critical alerts sent immediately
5. Monthly consolidation on the 1st

## Queries

```bash
# Find all vulnerabilities for a package
jq '.[] | select(.affected_packages[].name == "express")' data/vulnerabilities/*.json

# Get all critical issues from last 7 days
find logs/alerts -mtime -7 | xargs jq 'select(.severity == "critical")'

# List all installations this month
grep "$(date +%Y-%m)" logs/install-history/*.json
```

