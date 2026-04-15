# Guardog

Scan npm or PyPI packages for security threats before installing them.

## What it does

Runs a multi-layer security check:
- CVE lookup (Google OSV database)
- Package reputation (npm/PyPI/GitHub metadata)
- Malicious code pattern detection (30+ patterns)
- VirusTotal scan if API key is configured (70+ antivirus engines)

Returns one of three verdicts:
- **SILENT** - safe to install
- **WHINE** - suspicious, review before installing
- **BARK** - dangerous, do not install

## Usage

When the user invokes /guardog, run a security scan on the specified package.

Parse the arguments:
- First arg: package name
- Second arg (optional): ecosystem — `npm` (default) or `pypi`

Run the scan:
```
node ~/guardog/src/index.js analyze <package> [npm|pypi]
```

If ~/guardog doesn't exist, try to locate index.js via:
```
find ~ -name "index.js" -path "*/guardog/src/*" 2>/dev/null | head -1
```

## Reporting results

After the scan completes:
1. State the verdict clearly (SILENT / WHINE / BARK)
2. Summarize the key reasons
3. Give a clear install recommendation
4. For BARK or WHINE, suggest running /gstack-cso on any affected code

## Examples

/guardog lodash
/guardog requests pypi
/guardog some-random-package npm
