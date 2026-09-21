const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('resilience cycles escalate recurring categories and clear them after verified recovery', async () => {
  const { recordResilienceCycle } = await import('../src/resilience-loop.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-resilience-'));
  const statePath = path.join(root, 'resilience-state.json');
  const health = { ok: false, repairs: [], issues: ['No nightly scan roots selected.'] };
  const first = recordResilienceCycle({ phase: 'install', health, statePath, now: () => new Date('2026-09-21T00:00:00Z') });
  assert.equal(first.active.scan_roots.count, 1);
  assert.equal(first.escalations.length, 0);
  const second = recordResilienceCycle({ phase: 'nightly', health, statePath, now: () => new Date('2026-09-22T00:00:00Z') });
  assert.equal(second.active.scan_roots.count, 2);
  assert.equal(second.escalations[0].category, 'scan_roots');
  assert.equal(typeof second.escalations[0].nextAction, 'string');
  const recovered = recordResilienceCycle({ phase: 'nightly', health: { ok: true, repairs: [], issues: [] }, receipt: { status: 'complete', repairs: [], issues: [] }, statePath, now: () => new Date('2026-09-23T00:00:00Z') });
  assert.deepEqual(recovered.active, {});
  assert.equal(recovered.healthyStreak, 1);
  assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).cycles, 3);
});

test('resilience state stores issue categories rather than machine-specific issue text', async () => {
  const { recordResilienceCycle } = await import('../src/resilience-loop.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-resilience-private-'));
  const statePath = path.join(root, 'resilience-state.json');
  const privatePath = '/Users/example/private/customer-project';
  recordResilienceCycle({ phase: 'nightly', health: { ok: false, repairs: [], issues: [`Scan root unavailable: ${privatePath}`] }, statePath });
  assert.equal(fs.readFileSync(statePath, 'utf8').includes(privatePath), false);
});

test('a category recurring across different unresolved cycles still escalates', async () => {
  const { recordResilienceCycle } = await import('../src/resilience-loop.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-resilience-recur-'));
  const statePath = path.join(root, 'resilience-state.json');
  recordResilienceCycle({ phase: 'nightly', health: { ok: false, repairs: [], issues: ['No nightly scan roots selected.'] }, statePath });
  recordResilienceCycle({ phase: 'nightly', health: { ok: false, repairs: [], issues: ['VirusTotal quota exhausted.'] }, statePath });
  const recurring = recordResilienceCycle({ phase: 'nightly', health: { ok: false, repairs: [], issues: ['Scan root unavailable.'] }, statePath });
  assert.equal(recurring.active.scan_roots.count, 2);
  assert.equal(recurring.escalations[0].category, 'scan_roots');
});
