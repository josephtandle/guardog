# Guardog

Guardog checks packages before you trust them.

It looks for known vulnerabilities, weak reputation signals, suspicious metadata, risky code patterns, and optional VirusTotal findings. It works with npm and PyPI. It does not use AI tokens.

## The easy install

Requires Node.js 18 or newer.

```bash
npm install -g github:josephtandle/guardog
guardog setup --quick
guardog doctor
guardog analyze lodash npm
```

That is the safe path. Quick setup creates a local state folder. It does not install or change a background job. It does not change your global git hooks. It does not intercept normal `npm install` or `pip install` commands, and it does not send messages anywhere. Use `guardog install` when you want the pre-install scan.

Guardog stores its local state in `~/.guardog` on macOS and Linux, or `%USERPROFILE%\.guardog` on Windows.

## What works immediately

OSV scanning is ready as soon as Guardog is installed. It uses the public OSV.dev API and needs no account or API key. OSV currently documents no API rate limit.

```bash
guardog analyze lodash npm
guardog analyze requests pypi
```

Craig Soles' OSV-Scan guide inspired the simpler npm and pip install flow in version 1.2.0. Guardog keeps the useful part, a direct OSV check, while running it before the package manager instead of after.

```bash
guardog install npm install lodash@4.17.21
guardog install pip install requests==2.31.0
```

The original npm shorthand still works:

```bash
guardog install express
```

Guardog scans the named packages first. A `BARK` verdict blocks the guarded install. `SILENT` and `WHINE` continue to the package manager, with the warning printed for review.

Guardog fails closed when it cannot identify package names, including pip requirement files, URLs, and local paths. Scan those dependency files separately before installing them.

## VirusTotal

VirusTotal is optional. When configured with an API key, Guardog automatically derives the SHA-256 target hash from package metadata and runs VirusTotal scans. VirusTotal also stays available as an optional second opinion for a URL or file hash. Without an API key, Guardog still runs OSV lookups, reputation checks, pattern checks, and threat-intel cache checks.

Run the guided setup when you want to add a key:

```bash
guardog setup
```

You can get a personal API key from your VirusTotal Community account settings. Guardog saves it to your local Guardog state folder with owner-only file permissions. Keep the key private. If a key is pasted into a chat, terminal transcript, or public issue, rotate it before using it again.

VirusTotal's public API has usage restrictions, including restrictions on commercial products and services. Check the [official VirusTotal API terms and getting-started guide](https://docs.virustotal.com/reference/intro/getting-started) before using it in a business workflow.

To include VirusTotal in a scan, provide a URL or hash after the package and ecosystem:

```bash
guardog analyze example-package npm https://example.com/package.tgz
```

## GitHub API Configuration

Without `GITHUB_API_TOKEN`, the unauthenticated GitHub API allows only 60 requests per hour. When rate limits or network errors occur, Guarddog reports 'GitHub could not be checked' rather than treating the missing data as clean. Setting `GITHUB_API_TOKEN` raises the limit to 5000 requests per hour. Setting `GITHUB_API_TOKEN` in your environment or `.env` file is recommended.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| SILENT: SAFE | Safe to install (clean result, no findings) |
| SILENT: UNCONFIRMED | Signals found below warning threshold: review reasons before installing |
| WHINE: SUSPICIOUS | Suspicious: review before installing |
| WHINE: NOT_FOUND | Package does not exist in registry: verify spelling for typosquats |
| BARK: DANGER | Dangerous: do not install |

## What Guardog checks

1. Known advisories through [OSV.dev](https://google.github.io/osv.dev/api/)
2. Package reputation from npm, PyPI, RubyGems, and GitHub metadata
3. Code pattern analysis for risky package metadata and code snippets
4. Automatic VirusTotal scans when configured with an API key (or explicit URL/hash target)
5. Cached threat-intelligence findings when available

## Optional automation

Nothing runs in the background by default. If you want more protection, the full setup can configure it explicitly:

```bash
guardog setup
guardog updates enable
guardog hooks enable
```

Nightly scans use cron on macOS and Linux, and Task Scheduler on Windows. Global git hooks are skipped on Windows because the portable path is `guardog install`.

To scan a complete dependency file:

```bash
guard-dog-scan ./package.json
guardog batch ./examples/batch-example.json
```

## Security and privacy

Guardog has no external notification integration. Runtime history and secrets stay in the local Guardog state folder. Do not include keys, tokens, `.env` files, or unredacted scan logs in bug reports.

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/josephtandle/guardog/security/advisories/new).

## License

MIT
