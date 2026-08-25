"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

test("quick setup is local-only and VirusTotal keys are stored privately", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardog-setup-"));
  const previousHome = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = tempDir;

  try {
    fs.writeFileSync(path.join(tempDir, "config.json"), JSON.stringify({ guardedInstalls: true }));
    const { runQuickSetup, saveVirusTotalKey } = await import("../src/setup.js");
    const config = runQuickSetup();

    assert.equal(config.nightlyUpdates, false);
    assert.equal(config.gitPreCommitHook, false);
    assert.equal('guardedInstalls' in config, false);
    assert.equal('guardedInstalls' in JSON.parse(fs.readFileSync(path.join(tempDir, "config.json"), "utf8")), false);

    saveVirusTotalKey("synthetic-test-key");
    const envPath = path.join(tempDir, ".env");
    assert.match(fs.readFileSync(envPath, "utf8"), /^VIRUSTOTAL_API_KEY=synthetic-test-key$/m);
    assert.equal(fs.statSync(envPath).mode & 0o777, 0o600);
  } finally {
    if (previousHome === undefined) delete process.env.GUARDOG_HOME;
    else process.env.GUARDOG_HOME = previousHome;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
