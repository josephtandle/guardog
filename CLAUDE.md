# Guard-Dog

Package-level security scanner. Scans npm/pip packages for known CVEs,
malicious patterns, VirusTotal flags, and reputation signals.

## Decision Levels
- BARK (>=100): Danger, Telegram alert sent
- WHINE (50-99): Suspicious, warn user
- SILENT (<50): Safe, pass through

## Companion: /gstack-cso (code-level review)

Guard-dog catches bad packages. /gstack-cso catches bad code.
When a scan returns BARK or WHINE, also run /gstack-cso on the affected code:

  bash bin/run-cso.sh <path-to-code>

/gstack-cso runs OWASP Top 10 + STRIDE threat modeling. Complements guard-dog's
package-level analysis with code-level vulnerability review.

## Entry Point
  node src/index.js analyze <package> [ecosystem] [url]
  node src/index.js batch <packages.json>

## Cron
  Nightly at 02:30 GMT+8 via bin/cron-nightly-scan.sh
