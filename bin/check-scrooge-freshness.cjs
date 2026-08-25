#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const MAX_AGE_MS = 26 * 60 * 60 * 1000;
const DEFAULT_STATE_PATH = path.join(os.homedir(), ".myos", "workspace", "agents", "scrooge", "data", "reconciliation.json");
function option(name) { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : null; }
function checkScroogeFreshness({ statePath = DEFAULT_STATE_PATH, now = Date.now() } = {}) {
  let state;
  try { state = JSON.parse(fs.readFileSync(statePath, "utf8")); }
  catch (error) { return { ok: false, kind: "scrooge_reconciliation_missing_or_invalid", statePath, reason: error.code === "ENOENT" ? "missing" : "invalid_json" }; }
  const atMs = Date.parse(state?.at || "");
  if (!Number.isFinite(atMs)) return { ok: false, kind: "scrooge_reconciliation_missing_or_invalid", statePath, reason: "missing_or_invalid_timestamp" };
  const ageMs = Math.max(0, now - atMs);
  if (ageMs > MAX_AGE_MS) return { ok: false, kind: "scrooge_reconciliation_stale", statePath, ageHours: Number((ageMs / 3600000).toFixed(2)), maxAgeHours: 26 };
  return { ok: true, statePath, ageHours: Number((ageMs / 3600000).toFixed(2)), at: state.at };
}
async function main() {
  const check = checkScroogeFreshness({ statePath: option("--state-path") || process.env.SCROOGE_RECONCILIATION_PATH || DEFAULT_STATE_PATH, now: Number(option("--now") || Date.now()) });
  console.log(JSON.stringify(check));
  if (!check.ok) process.exitCode = 1;
}
if (require.main === module) main().catch((error) => { console.error(`[guard-dog] ${error.message}`); process.exitCode = 1; });
module.exports = { MAX_AGE_MS, DEFAULT_STATE_PATH, checkScroogeFreshness };
