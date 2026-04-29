# Guardog

Guardog is a package security scanner for npm and PyPI. It checks packages for known CVEs, reputation signals, suspicious metadata, malicious code patterns, optional VirusTotal results, and cached threat-intelligence findings before you install or commit dependency changes.

It runs locally and does not use OpenAI, YOLO, MyOS, Dispatch, Typeless, or any other AI/token service. Network lookups go to public package and security APIs such as npm, PyPI, OSV, GitHub Advisories, NVD, CISA KEV, and optional VirusTotal.

## Install From GitHub

Requires Node.js 18 or newer.

```bash
npm install -g github:josephtandle/guardog
guardog setup
```

The setup wizard creates a user-writable state folder at `~/.guardog` on macOS/Linux and `%USERPROFILE%\.guardog` on Windows. It asks:

1. Run Guardog every night at midnight?
2. Use Guardog before dependency installs?
3. Install a git pre-commit dependency hook?
4. Add a VirusTotal API key?

Nightly scans and global hooks are off unless you opt in.

## Usage

```bash
guardog analyze lodash npm
guardog analyze requests pypi
guardog batch ./packages.json
guardog doctor
```

For guarded npm installs, use Guardog as the pre-install wrapper:

```bash
guardog install left-pad
guardog install
```

`guardog install <package>` scans the requested package first. If Guardog returns `BARK`, it blocks the install. Otherwise it runs `npm install` with the same arguments.

## Nightly Scans

Nightly scans are disabled by default. Enable or disable them explicitly:

```bash
guardog updates enable
guardog updates status
guardog updates disable
```

By default, nightly scans search for `package.json` files under your home folder. To limit the scan:

```bash
GUARDOG_WORKSPACE=~/projects guardog nightly
```

On macOS/Linux, `guardog updates enable` installs a cron entry. On Windows, it installs a Task Scheduler entry named `GuardogNightlyScan`.

## Install Hooks

Guardog cannot universally intercept every installer on every operating system. The supported cross-platform install-time protection is:

```bash
guardog install <npm-package>
```

For git workflows, you can opt into a dependency scan before commits:

```bash
guardog hooks enable
```

On Windows, global git hook installation is skipped by default because shell hooks require Git Bash/compatible shell behavior. Use `guardog install` for the portable path.

## VirusTotal

VirusTotal is optional. Without it, Guardog still runs reputation checks, CVE lookups, pattern checks, and threat-intel cache checks.

The free tier is usually enough for light use: 4 requests/minute and 500/day.

Add or update the key with:

```bash
guardog setup
```

The key is saved in the user state folder, not inside the installed package.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| SILENT | Safe to install |
| WHINE | Suspicious; review before installing |
| BARK | Dangerous; do not install |

## What It Checks

1. CVE databases through OSV and related feeds
2. Package reputation from npm, PyPI, RubyGems, and GitHub metadata
3. Code pattern analysis for risky package metadata/code snippets
4. Optional VirusTotal scans when an API key and target are provided
5. Optional cached threat-intelligence findings

## Cross-Platform Notes

The default CLI path is Node-based and works on macOS, Windows, and Linux. Legacy Bash scripts remain for existing users, but the recommended install and setup flow is `npm install -g github:josephtandle/guardog` followed by `guardog setup`.

Runtime state lives in `~/.guardog` or `%USERPROFILE%\.guardog`, so global installs and package upgrades do not wipe scan history or secrets.

## License

MIT
