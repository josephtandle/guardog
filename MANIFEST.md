# Guard Dog 3.0 operations

Guard Dog protects supported package workflows, not the entire operating system.

## Local state

State is stored in `GUARDOG_HOME`, or `~/.guardog` by default.

- `config.json`: selected scan roots, schedule consent and local run time.
- `.env`: local VirusTotal credential, never include it in reports.
- `bin/nightly-runner.cjs`: Guard Dog-owned scheduler entry point.
- `data/last-nightly.json`: latest scan receipt, coverage and findings.
- `data/nightly.lock`: overlap protection for active nightly runs.

## Operations

Use `guardog doctor --repair` to inspect health and attempt bounded repairs.
Daily scans also check local health. Only previously enabled schedules can be
restored. Unknown runner files and scheduler conflicts require human attention.
Repairs must not weaken security checks or modify project dependencies.

Use `guardog updates status` to inspect actual OS scheduling and
`guardog nightly` to exercise a run. An empty or incomplete scan is not success.
Review the receipt's dependency count, configured roots, findings and missing
coverage. The machine must be available for its scheduler to run.

This release does not promise immediate external notifications, daily email
digests, monthly consolidation or automatic vulnerability remediation.
