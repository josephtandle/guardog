# Changelog

## 2.0.0 (2026-08-25)

Security capability and fail-safe behavior update based on external security audit, 2026-08-25:

- Fix 1: Deferred optional Telegram shared module require inside sendDangerAlert to prevent startup crashes.
- Fix 2: Updated guardedInstall spawnSync to handle Windows .cmd execution safely and catch spawn errors explicitly.
- Fix 3: Normalized CVE severity vocabulary (alias moderate to medium) and added warning fallback for unmapped severities.
- Fix 4: Raised SECURITY_COMPLAINTS reputation weight to reach WHINE threshold on its own, and rendered SILENT decisions with reasons as UNCONFIRMED with an informational icon instead of a green checkmark.
- Fix 5: Short-circuited missing registry packages to WHINE/NOT_FOUND verdict instead of scoring as low-threat safe packages.
- Fix 6: Derived VirusTotal target hash automatically from package tarball or PyPI metadata, polled URL analyses until completion, and failed 0-engine scans.
- Fix 7: Restricted trusted-provider allowlist to skip only reputation heuristics while still running objective VT, CVE, and pattern checks.
- Fix 8: Split decision notes from risk reasons so trusted provider notifications do not trigger UNCONFIRMED threat state on safe packages.
- Fix 9: Removed dead, unpatched duplicate module tree in src/alerts, src/core, and src/scanners.
- Fix 10: Discriminated GitHub API lookup failures to emit GITHUB_CHECK_FAILED and score 25 (UNCONFIRMED) instead of treating API rate limiting or errors as clean repository signals (found during verification of audit wave).

