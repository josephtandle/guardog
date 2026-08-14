# Learning

Record verified scan-policy improvements, false-positive patterns, and reusable guardrails here.

## 2026-08-14 MISTAKE LOGGED: guard-dog should validate against the active wave snapshot

Failure: The Guard Dog test read the stale primary-tree registry snapshot while the active Autonomizer wave was tracking versions in the worktree registry.
Cause: I assumed the nested repo parent tree was the authoritative version source for this rollout.
Correction: When validating Guard Dog version drift during an Autonomizer wave, point the test at the active worktree registry snapshot so the contract, registry, and package version are checked against the same release.
Guard: Do not mix primary-tree and worktree registry snapshots in the same version check.
