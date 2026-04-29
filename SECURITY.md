# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately instead of opening a public
issue with exploit details.

Send the affected package name, version, reproduction steps, and any relevant
logs or scan output to the repository owner through GitHub Security Advisories:

https://github.com/josephtandle/guardog/security/advisories/new

If GitHub Security Advisories are unavailable, open a minimal public issue that
requests a private security contact without including exploit details.

## Supported Versions

GuardDog is currently pre-1.1 public release software. Security fixes are
expected on the default branch first, then released from the latest tagged
version.

## Handling Secrets

Do not include API keys, tokens, `.env` files, scan cache contents, or runtime
logs in vulnerability reports unless they have been redacted.
