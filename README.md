# Guardog

A package security scanner for npm and PyPI. Checks packages for known CVEs, malicious code patterns, and reputation signals before you install them.

Works out of the box. No API keys required.

## Install

```bash
git clone https://github.com/josephtandle/guardog.git ~/guardog
cd ~/guardog
./install.sh
```

The installer handles dependencies, wires up the Claude Code `/guardog` skill, and optionally sets up a git pre-commit hook.

## Usage

**Command line:**
```bash
node ~/guardog/src/index.js analyze lodash npm
node ~/guardog/src/index.js analyze requests pypi
node ~/guardog/src/index.js analyze some-sketchy-package npm
```

**In Claude Code:**
```
/guardog lodash
/guardog requests pypi
```

**Batch scan a package.json:**
```bash
node ~/guardog/src/index.js batch path/to/package.json
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| SILENT | Safe to install |
| WHINE | Suspicious — review before installing |
| BARK | Dangerous — do not install |

## What it checks

1. **CVE database** — queries Google's OSV (Open Source Vulnerabilities) for known CVEs
2. **Package reputation** — checks npm/PyPI/GitHub for metadata signals (age, download count, missing repo, etc.)
3. **Code pattern analysis** — detects 30+ malicious patterns (eval abuse, obfuscation, credential harvesting, crypto miners)
4. **VirusTotal** — scans with 70+ antivirus engines (requires free API key, see below)

## VirusTotal — highly recommended

The free tier is enough for everyday use: 4 requests/minute, 500/day.

**Sign up:** https://www.virustotal.com/gui/join-us (takes 2 minutes)

**Add your key:**
```bash
echo "VIRUSTOTAL_API_KEY=your_key_here" > ~/guardog/.env
```

Without VirusTotal, Guardog still runs CVE lookups, reputation checks, and pattern analysis. With it, you also get 70+ antivirus engines on the actual package file.

## Git pre-commit hook

Automatically scans changed dependencies before every commit. Install.sh will offer to set this up globally, or do it manually:

```bash
mkdir -p ~/guardog/bin/hooks
cp ~/guardog/bin/git-precommit-hook.sh ~/guardog/bin/hooks/pre-commit
chmod +x ~/guardog/bin/hooks/pre-commit
git config --global core.hooksPath ~/guardog/bin/hooks
```

## npm postinstall hook

Scans packages automatically after every `npm install`. Add to any project's `package.json`:

```json
{
  "scripts": {
    "postinstall": "~/guardog/bin/npm-postinstall-hook.sh"
  }
}
```

## Nightly cron scan

Scans all `package.json` files under your home directory every night:

```bash
# Add to crontab (crontab -e):
30 2 * * * ~/guardog/bin/cron-nightly-scan.sh >> ~/guardog/data/cron.log 2>&1
```

To limit the scan to a specific directory:
```bash
GUARDOG_WORKSPACE=~/projects ~/guardog/bin/cron-nightly-scan.sh
```

## Trusted providers

Common packages (react, express, lodash, etc.) and trusted namespaces (`@babel/*`, `@types/*`, etc.) are whitelisted and skipped for speed. Edit `config/trusted-providers.json` to customize.

## Scoring

| Source | Weight |
|--------|--------|
| VirusTotal malicious vote | +30 per vote |
| VirusTotal suspicious vote | +20 per vote |
| CVE critical | +25 each |
| CVE high | +15 each |
| Malicious pattern (critical) | +30 each |
| No GitHub repo | +25 |
| Package age < 7 days | +20 |

Score >= 100: BARK. Score 50-99: WHINE. Score < 50: SILENT.

## License

MIT
