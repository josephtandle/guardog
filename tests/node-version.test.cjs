const assert = require('node:assert/strict');
const test = require('node:test');

test('runtime accepts only Node 24', async () => {
  const { assertSupportedNodeVersion } = await import('../src/node-version.js');
  assert.doesNotThrow(() => assertSupportedNodeVersion('24.0.0'));
  assert.doesNotThrow(() => assertSupportedNodeVersion('24.99.1'));
  assert.throws(() => assertSupportedNodeVersion('22.22.0'), /Node\.js 24\.x is required/);
  assert.throws(() => assertSupportedNodeVersion('26.0.0'), /Node\.js 24\.x is required/);
  assert.throws(() => assertSupportedNodeVersion('not-a-version'), /Node\.js 24\.x is required/);
});
