# Guard Dog contributor guide

Read README.md and guardog.md before changing behavior or describing protection.

The CLI is `node src/index.js`. Run `npm test` for offline regression tests.
`npm run test:live` makes external service calls and may use a locally configured key.

Never equate SILENT with guaranteed safety. Coverage and `installAllowed` are
separate from the warning threshold. Missing required evidence blocks guarded installs.
Audit exact installed or locked versions, never substitute latest for an unresolved version.
Do not upload private files or print credentials.

Nightly scans use `bin/nightly-scan.js` and explicitly configured scan roots.
Schedule registration must be read back from the OS. Self-repair is limited to
owned local state and previously authorized scheduling, never security bypasses.
Use independent review and cross-platform tests before publishing a release.
