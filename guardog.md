# Guard Dog skill

Use Guard Dog before installing npm dependencies and for recurring exact-version audits.
Official project: https://github.com/josephtandle/guardog. CLI: `guardog` (aliases `guarddog`, `guard-dog`).

1. Locate the installed command using the platform's command discovery, then run `guardog --version` and `guardog doctor`.
2. If missing or unhealthy, follow `GUARD_DOG_PROMPT.md`. Use `doctor --repair` for bounded supported repairs and verify the result.
3. Before supported npm installs, use `guardog install <package>`. Never fall back to a direct package-manager install when the gate blocks.
4. Audit existing projects with `guardog scan "<folder>"`. Report exact versions and coverage, including transitive dependencies.
5. Set up opted-in daily scans with `updates enable --workspace "<folder>" --time HH:MM`, inspect registration, and run `nightly` once.

Missing VirusTotal reports, API failures, and unresolved versions are incomplete protection. Never represent them as safe. VirusTotal queries and OSV advisories do not replace operating-system antivirus. Never upload private files, erase findings, or weaken checks to make installation succeed.
