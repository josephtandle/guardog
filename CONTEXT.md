# Guardog: Project Context
> Last updated: 2026-08-17

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

## Verdicts

- SILENT (score < 50): safe
- WHINE (score 50-99): suspicious
- BARK (score >= 100): dangerous, install blocked

## Known Issues / Next Steps

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
| `config/trusted-providers.json` | Package whitelist |
