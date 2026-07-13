"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { checkScroogeFreshness } = require("../bin/check-scrooge-freshness.cjs");
test("dead-man switch alerts for missing and 27-hour-old reconciliation state", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scrooge-freshness-"));
  const statePath = path.join(directory, "reconciliation.json");
  const now = Date.parse("2026-07-14T12:00:00Z");
  try {
    assert.equal(checkScroogeFreshness({ statePath, now }).ok, false);
    fs.writeFileSync(statePath, JSON.stringify({ at: "2026-07-13T09:00:00Z" }));
    assert.equal(checkScroogeFreshness({ statePath, now }).kind, "scrooge_reconciliation_stale");
    fs.writeFileSync(statePath, JSON.stringify({ at: "2026-07-14T11:00:00Z" }));
    assert.equal(checkScroogeFreshness({ statePath, now }).ok, true);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
