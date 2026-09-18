const test = require('node:test');
const assert = require('node:assert/strict');

test('removed packages retain confirmed malware findings and incomplete coverage', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const result = tree.evaluate({ success: false }, { signals: ['PACKAGE_NOT_FOUND'] }, 'removed-package', {
    status: 'complete', found: true, severity: { critical: 0, high: 0, medium: 1, low: 0 },
    vulnerabilities: [{ id: 'MAL-2026-1', summary: 'Malicious package' }]
  });
  assert.equal(result.action, 'BARK');
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.installAllowed, false);
});

test('established packages are not new because their latest version was just released', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const checker = new ReputationChecker({ reputation: {} });
  const signals = checker.analyzeSignals({ registry: { createdAt: '2015-01-01', publishDate: new Date().toISOString(), repository: 'https://github.com/example/project', weeklyDownloads: 10000 } });
  assert.equal(signals.includes('NEWLY_PUBLISHED'), false);
});

test('unverified complaints alone do not trigger a warning', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  assert.ok(tree.evaluateReputation({ signals: ['SECURITY_COMPLAINTS'] }, []) < 50);
});

test('unresolved version does not query historical OSV advisories', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  const checker = new CVEChecker({});
  let calls = 0;
  checker.checkOSV = async () => { calls++; return { vulnerabilities: [] }; };
  const result = await checker.checkCVEs('better-auth', 'npm');
  assert.equal(calls, 0);
  assert.equal(result.status, 'unavailable');
});

test('OSV failure is incomplete, while successful empty response is complete', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  const checker = new CVEChecker({});
  checker.checkOSV = async () => { throw new Error('503'); };
  assert.equal((await checker.checkCVEs('x', 'npm', '1.0.0')).status, 'unavailable');
  checker.checkOSV = async () => ({ vulnerabilities: [] });
  assert.equal((await checker.checkCVEs('x', 'npm', '1.0.0')).status, 'complete');
});

test('confirmed malware blocks even an allowlisted package', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: { maliciousVotes: 3 } }, { trustedProviders: ['x'], trustedNamespaces: [] });
  const decision = tree.evaluate({ success: true, found: true, maliciousVotes: 3 }, { signals: [] }, 'x', { status: 'complete', found: false }, null, true);
  assert.equal(decision.action, 'BARK');
  assert.equal(decision.installAllowed, false);
});

test('missing required coverage blocks installation without calling it malware', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const decision = tree.evaluate({ success: false, status: 'not_configured' }, { signals: [] }, 'x', { status: 'unavailable', found: false }, null, false);
  assert.equal(decision.coverage, 'incomplete');
  assert.equal(decision.installAllowed, false);
  assert.notEqual(decision.threat, 'SAFE');
  assert.notEqual(decision.threat, 'DANGER');
});
