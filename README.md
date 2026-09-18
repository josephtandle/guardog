# Guard Dog 3.0

VirusTotal requests are paced within each process, including retries and refreshes.
Separate processes or other software sharing the same API key can still exhaust its
quota. Rate limits leave coverage incomplete; they never turn into a clean result.

Guard Dog checks software packages before installation and rechecks your projects against current security information. Its command is `guardog`, with `guarddog` and `guard-dog` aliases. The official source is [josephtandle/guardog](https://github.com/josephtandle/guardog). Other projects with similar names are unrelated.

## Install with your AI assistant

Use the [installation prompt](GUARD_DOG_PROMPT.md). It guides your assistant through setup, a first audit, VirusTotal verification, scheduling, repairs, and a completion report.

For a terminal installation on macOS, Windows, or Linux, use Node 22 or newer (Node 24 LTS preferred):

```sh
npm install -g --ignore-scripts github:josephtandle/guardog#v3.0.1
guardog setup
guardog test
guardog scan "/your/project"
guardog doctor --repair
```

On Windows, substitute a quoted Windows folder such as `"C:\Users\You\Projects"`. All Sorted users should use the matching module installer instead of creating a second installation.

State lives in `~/.guardog` or `%USERPROFILE%\.guardog`, independently of the installation directory. `GUARDOG_HOME` selects another state folder. Upgrades preserve this state.

## Check before installing

```sh
guardog install lodash
guardog install npm install express@5.1.0
```

The guarded npm installer resolves the full dependency tree in temporary staging with scripts disabled. It checks exact versions and public npm artifact hashes, then requires completed security checks before installing the approved lockfile. Lifecycle scripts remain disabled after installation. Packages needing build scripts require a separate review.

Direct npm or pip commands bypass Guard Dog. Guard Dog does not intercept all terminal activity. Unsupported guarded installations, including pip, custom registries, workspaces and local/Git sources, stop with an explanation. They are not silently passed through.

## Audit existing projects

```sh
guardog scan "/your/project"
guard-dog-scan "/your/project/package.json" --json
guardog analyze node-ipc@10.1.1 npm
guardog analyze requests@2.32.3 pypi
```

Project audits read exact npm lockfile or installed metadata versions, including transitive dependencies. npm lockfile versions 1, 2 and 3 and shrinkwrap files are supported. Installed metadata takes precedence where present. Results distinguish installed from locked versions. A missing or unsupported inventory is incomplete, never a request to check latest instead. Python and Ruby packages can be analyzed individually; automatic project inventory currently covers npm.

## VirusTotal and coverage

OSV vulnerability checks need no API key. VirusTotal malware checks require your own key, entered locally with `guardog setup` or supplied through `VIRUSTOTAL_API_KEY`. GitHub metadata requests can use `GITHUB_API_TOKEN` to reduce rate limits. Never paste keys into chat or bug reports.

VirusTotal checks SHA-256 reports for the exact package artifact. Old known reports request reanalysis; that request does not count as a fresh result. Reports with no completed engine verdicts, unknown hashes, old results, authentication failures and rate limits remain incomplete. No private files are uploaded. An explicitly supplied URL checks URL reputation, not its downloaded file contents.

Guarded installs require complete OSV and VirusTotal checks and no disqualifying findings. Without a VirusTotal key you can still inspect vulnerability findings, but guarded installs remain blocked. The default freshness limit for stored VirusTotal reports is 24 hours. API usage and access depend on your VirusTotal plan; see its [official API documentation](https://docs.virustotal.com/reference/overview).

| Result | Meaning |
| --- | --- |
| BARK | Serious evidence found; installation blocked. |
| WHINE | Warning signals need review; installation blocked. |
| SILENT | The completed checks did not reach a warning threshold. Read coverage too. |
| INCOMPLETE | Required evidence is missing. It is not a safe result. |

Audit exit codes are 0 for completed coverage, 1 for serious findings, and 2 for incomplete coverage or operational failure. A completed audit can still contain warnings or lower-severity advisories. Guarded installation has the stricter approval policy.

## Daily scans and self-repair

```sh
guardog updates enable --workspace "/your/workspace" --time "02:30"
guardog updates status
guardog nightly
guardog doctor --repair
```

Choose the folders and local run time explicitly. Scheduling uses cron on Mac/Linux and Task Scheduler on Windows, with registration readback. A scan receipt records the last run, project and dependency counts, danger and coverage gaps. An empty run is not reported as successful protection.

Each daily run checks its health first. Safe repairs restore missing state directories, restrict credential-file permissions on POSIX systems, and restore an owned runner or previously enabled missing schedule. Unknown files and jobs are preserved. Overlap and run-time limits prevent endless repair loops. Service retries are bounded. Credentials, unsupported inventories and persistent service outages remain visible for action. Repairs never weaken checks or alter project dependencies.

The computer must be available for its scheduler. Use `guardog updates disable` to remove the owned schedule. `guardog doctor --json` provides machine-readable health. Optional Git hooks are secondary commit checks, not pre-install protection.

## Scope and verification

Guard Dog protects the package workflow. It is not a replacement for operating-system antivirus and does not watch every file or process. Metadata pattern checks are not a full package-source review. No scan guarantees software is harmless.

`npm test` runs regression and real packed-install tests. CI runs these on Windows, macOS and Linux with Node 22 and 24. Scheduler tests exercise platform command construction and readback without installing real tasks. `npm run test:live` separately exercises public services and may consume API quota. See the release verification record for actual platform results.

Report security issues through [GitHub Security Advisories](https://github.com/josephtandle/guardog/security/advisories/new). License: MIT.
