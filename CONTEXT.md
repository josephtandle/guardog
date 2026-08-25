# Guardog: Project Context
> Last updated: 2026-08-26

## What It Is

A public npm/PyPI package security scanner packaged from the internal `guard-dog` agent and published to GitHub for Mastermind students. Scans packages before install using CVE lookups (OSV), reputation checks, malicious code pattern analysis, and optional VirusTotal results.

Works out of the box with no API keys. VirusTotal is optional and subject to VirusTotal's API terms.

## URLs / Access

- GitHub: https://github.com/josephtandle/guardog
- Install: `npm install -g github:josephtandle/guardog && guardog setup --quick`

## App Location

- Agent source (live): `~/.myos/workspace/agents/guard-dog/`
- Default install path for students: `~/guardog/`
- Own git repo: yes (initialized 2026-04-15, pushed to `josephtandle/guardog`)

## Tech Stack

- Node.js 18+ (ESM), built-in fetch, dotenv
- No build step. No server. CLI tool only.
- Optional Claude Code skill: `guardog.md`

## Environment Variables

- `VIRUSTOTAL_API_KEY`: optional, enables VirusTotal URL and file-hash results
- `GITHUB_API_TOKEN`: optional, increases GitHub API rate limits
- User configuration is loaded from `~/.guardog/.env`

## Key Endpoints / Commands

```bash
guardog analyze <package> [npm|pypi]
guardog batch <packages.json>
guardog test
```

The optional `guardog.md` Claude Code skill is included in the repository. The installer does not change Claude Code settings or skills automatically.

## Verdicts (v2.0.0)

- SILENT / SAFE (score < 50, no risk signals): checked and clean
- SILENT / UNCONFIRMED (score < 50 but risk signals present): NOT an all-clear. The signals scored
  below the warning threshold, and they are printed. Renders with an info icon, never a green check.
- WHINE / SUSPICIOUS (score 50-99): suspicious
- WHINE / NOT_FOUND (short-circuit): the package does not exist in the registry, so nothing could be
  checked. Possible typosquat. Never rendered as safe.
- BARK / DANGER (score >= 100): dangerous, install blocked

Informational notes (for example "trusted provider, reputation heuristics skipped") are kept
separate from risk reasons and never trigger UNCONFIRMED.

The governing rule: "could not determine" never serializes into the same shape as "determined to be
clean". A check that fails must produce a named, scored signal, not an absence.

## Known Issues / Next Steps

- Set `GITHUB_API_TOKEN`. Unauthenticated GitHub allows only 60 requests/hour, and that quota is
  shared across every scan. Without it, GuardDog reports "GitHub could not be checked" rather than
  a clean result, but the reputation signal is genuinely unavailable. With it, 5000/hour.
- Telegram alerting was REMOVED in v1.2.0 to make the package standalone-safe. The BARK branch
  prints its banner and sends nothing.
- Anyone still on a pre-2.0.0 install should pull. A SILENT from an older version is close to
  meaningless, see the 2026-08-25 audit in CHANGELOG.md.
- Giveaway page not yet built on workshop site (next step)
- `data/` and `logs/` are gitignored, so students start with empty history
- `setup-logging-structure.sh`, `mission-control-trigger.js`, internal ops scripts excluded from public repo

## Files to Know

| File | Purpose |
|------|---------|
| `src/index.js` | Main orchestrator |
| `install.sh` | Student installer |
| `guardog.md` | Optional Claude Code skill for manual installation |
| `bin/git-precommit-hook.sh` | Pre-commit integration |
| `config/trusted-providers.json` | Package allowlist. Skips reputation heuristics ONLY, not CVE/VT/pattern checks |
| `tests/audit-findings.test.cjs` | T1-T14, one binary regression test per audit finding |
| `CHANGELOG.md` | The 2026-08-25 audit and all ten fixes |
