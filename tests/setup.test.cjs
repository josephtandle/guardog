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
    if (process.platform !== 'win32') assert.equal(fs.statSync(envPath).mode & 0o777, 0o600);
  } finally {
    if (previousHome === undefined) delete process.env.GUARDOG_HOME;
    else process.env.GUARDOG_HOME = previousHome;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('quick setup refuses malformed config without replacing bytes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-invalid-config-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = dir;
  try {
    const file = path.join(dir, 'config.json');
    const original = '{"scanRoots": ["precious"], broken';
    fs.writeFileSync(file, original);
    const { runQuickSetup } = await import('../src/setup.js');
    assert.throws(() => runQuickSetup(), /config/i);
    assert.equal(fs.readFileSync(file, 'utf8'), original);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('requested scheduler failure rejects setup as incomplete', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-failed-schedule-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = dir;
  try {
    const { runSetup } = await import('../src/setup.js');
    const answers = ['yes', 'yes', dir, 'no'];
    await assert.rejects(runSetup({ input: { isTTY: false }, output: { isTTY: false },
      question: async () => answers.shift(),
      installSchedule: () => ({ ok: false, message: 'scheduler unavailable' }),
      removeHook: () => ({ ok: true, message: 'No hook' })
    }), error => error.exitCode === 2);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'config.json'))).nightlyUpdates, false);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('secret entry hides TTY input and skips non-TTY streams', async () => {
  const { PassThrough, Writable } = require('node:stream');
  const { readHiddenKey } = await import('../src/setup.js');
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => {};
  let displayed = '';
  const output = new Writable({ write(chunk, _encoding, done) { displayed += chunk.toString(); done(); } });
  output.isTTY = true;
  const pending = readHiddenKey(input, output);
  input.write('synthetic-secret\r');
  assert.equal(await pending, 'synthetic-secret');
  assert.equal(displayed.includes('synthetic-secret'), false);
  assert.equal(await readHiddenKey({ isTTY: false }, output), null);
  input.destroy();
});
