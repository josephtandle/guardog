const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('T1: static imports and requires in src/ stay within package root', () => {
  const srcDir = path.resolve(__dirname, '../src');
  const packageRootDir = path.resolve(__dirname, '..');

  function getJsFiles(dir) {
    let results = [];
    const list = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of list) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results = results.concat(getJsFiles(fullPath));
      } else if (entry.isFile() && entry.name.endsWith('.js')) {
        results.push(fullPath);
      }
    }
    return results;
  }

  const jsFiles = getJsFiles(srcDir);
  const importRequireRegex = /(?:import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;

  for (const filePath of jsFiles) {
    const content = fs.readFileSync(filePath, 'utf8');
    let match;
    while ((match = importRequireRegex.exec(content)) !== null) {
      const specifier = match[1] || match[2];
      if (specifier) {
        if (specifier.startsWith('../../')) {
          assert.fail(`File ${path.relative(packageRootDir, filePath)} imports/requires external specifier '${specifier}'`);
        }
        if (specifier.startsWith('.')) {
          const resolvedPath = path.resolve(path.dirname(filePath), specifier);
          const relativeToRoot = path.relative(packageRootDir, resolvedPath);
          if (relativeToRoot.startsWith('..') || (path.isAbsolute(relativeToRoot) && !resolvedPath.startsWith(packageRootDir))) {
            assert.fail(`File ${path.relative(packageRootDir, filePath)} targets path outside package root: '${specifier}'`);
          }
        }
      }
    }
  }
});

test('T2: updateSeverityCounts with moderate severity increments counts.medium', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  const checker = new CVEChecker({});
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  checker.updateSeverityCounts(counts, [{ id: 'GHSA-1', severity: 'moderate' }]);
  assert.equal(counts.medium, 1);
});

test('T3: updateSeverityCounts with unrecognized severity increments counts.medium', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  const checker = new CVEChecker({});
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  checker.updateSeverityCounts(counts, [{ id: 'GHSA-2', severity: 'catastrophic' }]);
  assert.equal(counts.medium, 1);
});

test('T4: evaluateReputation with SECURITY_COMPLAINTS returns >= 50', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const reasons = [];
  const score = dt.evaluateReputation({ signals: ['SECURITY_COMPLAINTS'] }, reasons);
  assert.ok(score >= 50, `Expected score >= 50, got ${score}`);
});

test('T5: evaluate returning SILENT with reasons sets UNCONFIRMED and formatDecision omits green check', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const scanResults = { success: true, found: false };
  const reputationData = { signals: ['DEPRECATED'] };
  const decision = dt.evaluate(scanResults, reputationData, 'untrusted-pkg', null, null, false);
  assert.equal(decision.action, 'SILENT');
  assert.equal(decision.threat, 'UNCONFIRMED');
  const formatted = dt.formatDecision(decision);
  assert.ok(!formatted.includes('✅'), 'Formatted output should not contain ✅');
  assert.ok(formatted.includes('ℹ️'), 'Formatted output should contain ℹ️');
});

test('T6: evaluate with PACKAGE_NOT_FOUND returns WHINE/NOT_FOUND', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const decision = dt.evaluate({ success: true, found: false }, { signals: ['PACKAGE_NOT_FOUND'] }, 'missing-pkg');
  assert.equal(decision.action, 'WHINE');
  assert.equal(decision.threat, 'NOT_FOUND');
  assert.notEqual(decision.threat, 'SAFE');
});

test('T7: parseResults on payload with empty last_analysis_stats returns success: false', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const scanner = new VirusTotalScanner({ virustotal: { apiKey: 'dummy-key', baseUrl: 'https://vt', timeoutMs: 1000 } });
  const res = scanner.parseResults({ data: { attributes: { last_analysis_stats: {} } } });
  assert.equal(res.success, false);
  assert.equal(res.error, 'VirusTotal returned no engine results');
});

test('T8: trusted provider carrying critical CVE produces BARK or WHINE', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: ['lodash'], trustedNamespaces: [], trustedScopes: {} }
  );
  const cveResults = {
    found: true,
    severity: { critical: 2, high: 0, medium: 0, low: 0 }
  };
  const decision = dt.evaluate({ success: true, found: true, maliciousVotes: 0 }, { signals: [] }, 'lodash', cveResults);
  assert.ok(decision.action === 'WHINE' || decision.action === 'BARK', `Expected WHINE or BARK, got ${decision.action}`);
  assert.notEqual(decision.action, 'SILENT');
});

test('T9: evaluate() for a trusted provider with NO risk signals returns threat SAFE and formatDecision output does NOT contain Not a clean result', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: ['lodash'], trustedNamespaces: [], trustedScopes: {} }
  );
  const decision = dt.evaluate({ success: true, found: true, maliciousVotes: 0 }, { signals: [] }, 'lodash');
  assert.equal(decision.threat, 'SAFE');
  assert.notEqual(decision.threat, 'UNCONFIRMED');
  const formatted = dt.formatDecision(decision);
  assert.ok(!formatted.includes('Not a clean result'), 'Formatted output should not contain Not a clean result');
});

test('T10: evaluate() returning SILENT WITH a real risk reason still returns UNCONFIRMED and formatDecision DOES contain Not a clean result', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const decision = dt.evaluate({ success: true, found: true, maliciousVotes: 0 }, { signals: ['DEPRECATED'] }, 'untrusted-pkg');
  assert.equal(decision.action, 'SILENT');
  assert.equal(decision.threat, 'UNCONFIRMED');
  const formatted = dt.formatDecision(decision);
  assert.ok(formatted.includes('Not a clean result'), 'Formatted output should contain Not a clean result');
});

test('T11: analyzeSignals() given github result { ok: false, error: "rate limited", rateLimited: true } includes GITHUB_CHECK_FAILED and not SECURITY_COMPLAINTS', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const checker = new ReputationChecker({ reputation: {} });
  const results = {
    registry: { repository: 'https://github.com/foo/bar' },
    github: { ok: false, error: 'rate limited', rateLimited: true }
  };
  const signals = checker.analyzeSignals(results);
  assert.ok(signals.includes('GITHUB_CHECK_FAILED'), 'Expected signals to include GITHUB_CHECK_FAILED');
  assert.ok(!signals.includes('SECURITY_COMPLAINTS'), 'Expected signals not to include SECURITY_COMPLAINTS');
});

test('T12: evaluateReputation() with signals ["GITHUB_CHECK_FAILED"] returns >= 25 and pushes reason containing UNKNOWN', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const reasons = [];
  const score = dt.evaluateReputation({ signals: ['GITHUB_CHECK_FAILED'] }, reasons);
  assert.ok(score >= 25, `Expected score >= 25, got ${score}`);
  assert.ok(reasons.some(r => r.includes('UNKNOWN')), 'Expected a reason string containing UNKNOWN');
});

test('T13: evaluate() with signals ["GITHUB_CHECK_FAILED"] returns SILENT and UNCONFIRMED, never SAFE', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const decision = dt.evaluate({ success: true, found: true, maliciousVotes: 0 }, { signals: ['GITHUB_CHECK_FAILED'] }, 'untrusted-pkg');
  assert.equal(decision.action, 'SILENT');
  assert.equal(decision.threat, 'UNCONFIRMED');
  assert.notEqual(decision.threat, 'SAFE');
});

test('T14: evaluate() with signals ["GITHUB_CHECK_FAILED", "DEPRECATED"] returns SILENT and UNCONFIRMED for score 40', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const dt = new DecisionTree(
    { decisionThresholds: { maliciousVotes: 5, suspiciousVotes: 3 } },
    { trustedProviders: [], trustedNamespaces: [], trustedScopes: {} }
  );
  const decision = dt.evaluate({ success: true, found: true, maliciousVotes: 0 }, { signals: ['GITHUB_CHECK_FAILED', 'DEPRECATED'] }, 'untrusted-pkg');
  assert.equal(decision.action, 'SILENT');
  assert.equal(decision.threat, 'UNCONFIRMED');
});

