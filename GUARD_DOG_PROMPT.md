# Install Guard Dog 3.0.0

Copy the prompt below into your AI assistant. It needs access to your computer's terminal.

---

Install or upgrade Guard Dog and prove the protection is working.

Use this exact project: https://github.com/josephtandle/guardog. Guard Dog is the product name. `guardog`, `guarddog`, and `guard-dog` are commands for the same product. Do not substitute another project called GuardDog or invent a replacement implementation.

1. Detect my operating system, shell, Node version, existing installation, and project folder. Read the release instructions. Guard Dog requires Node 22 or newer; prefer Node 24 LTS for a new installation. Preserve settings and credentials. Explain decisions in plain English.

2. For the standalone release, install the official pinned tag with `npm install -g --ignore-scripts github:josephtandle/guardog#v3.0.0`. For All Sorted, use its matching module installer instead of creating a duplicate installation. Verify the executable location and `guardog --version`. If permissions or PATH fail, diagnose the actual error, use a user-owned install directory, and retry at most twice. Do not run arbitrary downloaded repair scripts or use administrator privileges automatically.

3. Run `guardog setup --quick`, then help me configure VirusTotal locally using `guardog setup`. Never ask for an API key in chat, print it, or include it in a report. Without a key, vulnerability audits still run, but malware coverage is incomplete and guarded installation stays blocked. A stored key is not proof it works: run `guardog test` and report the actual authentication and service results.

4. Identify the project or workspace I want protected. If unclear, ask me for the folder. Run `guardog scan "<project folder>"`. Inspect its exact-version inventory, findings, and missing checks. npm lockfiles and installed npm metadata are supported, including transitive dependencies. Unsupported inventories must be reported, never silently replaced with latest registry versions. Do not install or execute malicious demonstration packages. Explain any detected vulnerability without automatically modifying my project.

5. Configure daily scans after confirming my chosen folders and local run time. Run `guardog updates enable --workspace "<workspace folder>" --time "02:30"`. Read back the OS registration with `guardog updates status`. If there is a central automation calendar, register the schedule there as required. Run `guardog nightly` once and inspect the receipt shown by `guardog doctor`. A schedule alone, an empty scan, or a saved setting is not successful protection.

6. Use `guardog doctor --repair` for supported repairs. It can restore its local state and a previously enabled missing schedule. Check the result after every repair. Stop retrying after two failed attempts, preserve diagnostic evidence, and identify the exact remaining problem. Never disable a security check, change a threat threshold, erase findings, rotate credentials, or upgrade project dependencies as a repair shortcut.

7. Explain how to use `guardog install <npm-package>` before future installations. This command checks the resolved dependency tree and artifact hashes, requires completed checks, and keeps lifecycle scripts disabled. Direct npm/pip commands bypass this protection. Unsupported installation types are blocked with an explanation. A Git hook runs after dependencies may already be installed and is not a replacement for the install gate.

8. Leave a short completion report: installed version and path, scan roots, number of exact versions checked, findings, missing coverage, VirusTotal authentication and report freshness, OS schedule and time, last completed run, repairs performed, and anything I need to do. If a step failed, say setup is incomplete and give the next specific action.

Guard Dog protects the package workflow. It is not operating-system antivirus, does not watch every file, and cannot guarantee software is harmless. VirusTotal file-hash lookups retrieve current stored intelligence; old known reports can request a rescan, which remains incomplete until fresh results exist. Do not upload private files. SILENT means no warning threshold was reached, so always read coverage too.
