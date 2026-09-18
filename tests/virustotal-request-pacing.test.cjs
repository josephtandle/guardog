const test = require('node:test');
const assert = require('node:assert/strict');

function harness(key, responses) {
  let now = 0;
  const calls = [];
  return {
    config: { virustotal: { apiKey: key, baseUrl: 'https://vt.invalid', timeoutMs: 20 } },
    runtime: {
      now: () => now,
      wait: async milliseconds => { now += milliseconds; },
      fetch: async (url, options) => {
        calls.push({ url, time: now, method: options.method || 'GET', aborted: options.signal.aborted });
        const response = responses.shift();
        return { ok: response.status === 200, status: response.status, headers: { get: () => '0' }, json: async () => response.body || {} };
      }
    },
    calls
  };
}
const hash = 'a'.repeat(64);
const stale = { data: { attributes: { last_analysis_date: 1, last_analysis_stats: { malicious: 0, harmless: 5 } } } };

test('artifact lookup and stale report refresh each reserve a request slot', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-refresh', [{ status: 200, body: stale }, { status: 200 }]);
  const result = await new VirusTotalScanner(h.config, h.runtime).scan(hash);
  assert.equal(result.refreshRequested, true);
  assert.deepEqual(h.calls.map(call => [call.method, call.time]), [['GET', 0], ['POST', 16000]]);
  assert.ok(h.calls.every(call => !call.aborted));
});

test('concurrent scanner instances sharing an API key share slots', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-concurrent', [{ status: 404 }, { status: 404 }, { status: 404 }]);
  const first = new VirusTotalScanner(h.config, h.runtime);
  const second = new VirusTotalScanner(h.config, h.runtime);
  await Promise.all([first.getFileReport(hash), second.getFileReport(hash), first.getFileReport(hash)]);
  assert.deepEqual(h.calls.map(call => call.time), [0, 16000, 32000]);
});

test('retry reserves another full slot, but unauthorized requests never retry', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-retry', [{ status: 429 }, { status: 404 }]);
  await new VirusTotalScanner(h.config, h.runtime).getFileReport(hash);
  assert.deepEqual(h.calls.map(call => call.time), [0, 16000]);
  const denied = harness('pacing-unauthorized', [{ status: 401 }]);
  const result = await new VirusTotalScanner(denied.config, denied.runtime).scan(hash);
  assert.equal(result.status, 'unauthorized');
  assert.equal(denied.calls.length, 1);
});

test('URL submission and all analysis polls reserve slots', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-url', [
    { status: 200, body: { data: { id: 'analysis-id' } } },
    { status: 200, body: { data: { attributes: { status: 'queued' } } } },
    { status: 200, body: { data: { attributes: { status: 'completed', stats: { harmless: 5 } } } } }
  ]);
  const result = await new VirusTotalScanner(h.config, h.runtime).scan('https://example.test/package');
  assert.equal(result.success, true);
  assert.deepEqual(h.calls.map(call => call.time), [0, 16000, 32000]);
});

test('time spent waiting for a slot does not consume the request timeout', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-timeout', [{ status: 404 }, { status: 404 }]);
  const advance = h.runtime.wait;
  h.runtime.wait = async milliseconds => {
    await new Promise(resolve => setTimeout(resolve, 40));
    await advance(milliseconds);
  };
  const scanner = new VirusTotalScanner(h.config, h.runtime);
  await scanner.getFileReport(hash);
  const second = await scanner.getFileReport(hash);
  assert.equal(second.status, 'not_found');
  assert.ok(h.calls.every(call => !call.aborted));
});
