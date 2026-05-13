# Guardog — Project Context
> Last updated: 2026-04-15

## What It Is

A public npm/PyPI package security scanner packaged from the internal `guard-dog` agent and published to GitHub for Mastermind students. Scans packages before install using CVE lookups (Google OSV), reputation checks (npm/PyPI/GitHub), malicious code pattern analysis (30+ patterns), and optional VirusTotal scanning (70+ AV engines). Includes a Claude Code `/guardog` skill, `install.sh`, git pre-commit hook, and npm postinstall hook.

Works out of the box with no API keys. VirusTotal is optional but highly recommended (free tier, 2-min signup).

## URLs / Access

- GitHub: https://github.com/josephtandle/guardog
- Install: `git clone https://github.com/josephtandle/guardog.git ~/guardog && cd ~/guardog && ./install.sh`

## App Location

- Agent source (live): `~/.myos/workspace/agents/guard-dog/`
- Default install path for students: `~/guardog/`
- Own git repo: yes (initialized 2026-04-15, pushed to `josephtandle/guardog`)

## Tech Stack

- Node.js (ESM), better-sqlite3, dotenv, node-fetch
- No build step. No server. CLI tool only.
- Claude Code skill: `guardog.md` (installed to `~/.claude/skills/` by install.sh)

## Environment Variables

- `VIRUSTOTAL_API_KEY` — optional, enables 70+ AV engine scanning. Free tier: 4 req/min, 500/day.
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` — optional, sends BARK alerts to Telegram
- `GITHUB_API_TOKEN` — optional, increases GitHub API rate limits
- Loaded from `~/guardog/.env` (local to install dir, not workspace root)

## Key Endpoints / Commands

```bash
node ~/guardog/src/index.js analyze <package> [npm|pypi]
node ~/guardog/src/index.js batch <packages.json>
node ~/guardog/src/index.js test
```

In Claude Code: `/guardog <package> [npm|pypi]`

## Verdicts

- SILENT (score < 50): safe
- WHINE (score 50-99): suspicious
- BARK (score >= 100): dangerous, Telegram alert sent

## Known Issues / Next Steps

- Giveaway page not yet built on workshop site (next step)
- `data/` and `logs/` are gitignored — students start with empty history
- `setup-logging-structure.sh`, `mission-control-trigger.js`, internal ops scripts excluded from public repo

## Files to Know

| File | Purpose |
|------|---------|
| `src/index.js` | Main orchestrator |
| `install.sh` | Student installer |
| `guardog.md` | Claude Code skill |
| `bin/git-precommit-hook.sh` | Pre-commit integration |
| `bin/npm-postinstall-hook.sh` | Post-install integration |
| `bin/cron-nightly-scan.sh` | Nightly cron (respects `GUARDOG_WORKSPACE` env var) |
| `config/trusted-providers.json` | Package whitelist |
