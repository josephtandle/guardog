# Guard Dog quick start

Use [the installation prompt](GUARD_DOG_PROMPT.md) to have your assistant complete setup and verify it.

With Node 22 or newer installed:

```sh
npm install -g --ignore-scripts github:josephtandle/myos-guard-dog#v4.0.1
myos-guard-dog setup
myos-guard-dog test
myos-guard-dog scan "/your/project"
myos-guard-dog updates enable --workspace "/your/workspace" --time "02:30"
myos-guard-dog nightly
myos-guard-dog doctor --repair
```

`doctor --repair` is required after upgrading from a previous Guard Dog release. It preserves `~/.guardog` state and updates a previously enabled owned nightly runner to the current package.

On Windows, use your actual folder, such as `"C:\Users\You\Projects"`. Keep the quotes on all platforms.

VirusTotal needs your own API key. Enter it locally during setup. Without it, OSV vulnerability checks are available but malware coverage is incomplete. Guarded installs require completed checks.

`guardog install lodash` resolves and checks the npm dependency tree before installing it with lifecycle scripts disabled. Direct package-manager commands bypass Guard Dog. Unsupported guarded installs, including pip, are rejected rather than run without complete artifact verification. Individual PyPI versions can still be checked with `guardog analyze requests@2.32.3 pypi`.

Daily scans use the folders you selected. The computer must be available for its scheduler to run. Read `guardog doctor` to see actual registration and the last scan receipt. `--repair` performs bounded repairs to Guard Dog state and a previously enabled missing schedule; it does not change your project packages.

BARK indicates serious findings. WHINE asks for review. SILENT means the completed checks did not reach a warning threshold. INCOMPLETE means checks are missing; it is not a clean bill of health.
