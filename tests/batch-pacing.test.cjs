const test = require('node:test');
const assert = require('node:assert/strict');

test('batch leaves VirusTotal pacing to the shared request queue', async () => {
  const { GuardDog } = await import('../src/index.js');
  const delays = [];
  const original = global.setTimeout;
  global.setTimeout = (callback, delay) => { delays.push(delay); callback(); };
  try {
    await GuardDog.prototype.batchAnalyze.call({ scanner: {}, analyze: async () => ({ decision: { action: 'SILENT', coverage: 'complete', installAllowed: true } }) }, [{ name: 'fixture', version: '1.0.0' }]);
    assert.ok(delays.every(delay => delay <= 250), 'do not double-charge package and request pacing');
  } finally { global.setTimeout = original; }
});
