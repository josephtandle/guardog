const test = require('node:test');
const assert = require('node:assert/strict');
test('OSV CVSS vector is classified critical rather than downgraded', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  assert.equal(new CVEChecker({}).parseSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), 'critical');
});
