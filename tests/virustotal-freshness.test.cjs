const test = require('node:test');
const assert = require('node:assert/strict');

test('old VirusTotal report cannot be presented as current protection', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const scanner = new VirusTotalScanner({ virustotal: { apiKey: 'fixture', baseUrl: 'https://example.test', timeoutMs: 1000 } });
  const result = scanner.parseResults({ data: { attributes: { last_analysis_date: 100, last_analysis_stats: { malicious: 0, undetected: 60 } } } });
  assert.equal(result.stale, true);
});

test('authentication failure is not retried or reported as clean', async t => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const scanner = new VirusTotalScanner({ virustotal: { apiKey: 'fixture', baseUrl: 'https://example.test', timeoutMs: 1000 } });
  let count = 0;
  t.mock.method(globalThis, 'fetch', async () => { count++; return new Response('{}', { status: 401 }); });
  const result = await scanner.scan('a'.repeat(64));
  assert.equal(result.success, false);
  assert.equal(result.status, 'unauthorized');
  assert.equal(count, 1);
});

test('all engines timing out is not a successful scan', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const scanner = new VirusTotalScanner({ virustotal: { apiKey: 'fixture' } });
  assert.equal(scanner.parseResults({ data: { attributes: { last_analysis_date: Date.now() / 1000, last_analysis_stats: { timeout: 60 } } } }).success, false);
});
