/**
 * Guard Dog Test Suite
 * Tests all components and integration
 */

import { existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { GuardDog } from '../src/index.js';
import { CVEChecker } from '../src/cve-checker.js';
import { PatternAnalyzer } from '../src/pattern-analyzer.js';

class TestRunner {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.tests = [];
  }

  async run(name, fn) {
    try {
      await fn();
      this.passed++;
      this.tests.push({ name, status: 'PASS' });
      console.log(`✅ ${name}`);
    } catch (error) {
      this.failed++;
      this.tests.push({ name, status: 'FAIL', error: error.message });
      console.log(`❌ ${name}: ${error.message}`);
    }
  }

  assert(condition, message) {
    if (!condition) {
      throw new Error(message || 'Assertion failed');
    }
  }

  summary() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST SUMMARY');
    console.log('='.repeat(60));
    console.log(`✅ Passed: ${this.passed}`);
    console.log(`❌ Failed: ${this.failed}`);
    console.log(`📊 Total:  ${this.passed + this.failed}`);
    console.log('='.repeat(60) + '\n');
    
    return this.failed === 0;
  }
}

async function runTests() {
  console.log('\n🐕 Guard Dog Test Suite\n');
  
  const test = new TestRunner();
  let guardDog;

  // Initialize Guard Dog
  await test.run('Initialize Guard Dog', async () => {
    guardDog = new GuardDog();
    test.assert(guardDog, 'Guard Dog should initialize');
    test.assert(guardDog.reputation, 'Reputation checker should be initialized');
    test.assert(guardDog.decisionTree, 'Decision tree should be initialized');
    test.assert(guardDog.telegram, 'Telegram alert should be initialized');
  });

  // Test trusted providers
  await test.run('Trusted providers detection', async () => {
    test.assert(
      guardDog.decisionTree.isTrustedProvider('react'),
      'Should recognize trusted provider'
    );
    test.assert(
      guardDog.decisionTree.isTrustedProvider('@babel/core'),
      'Should recognize trusted namespace'
    );
    test.assert(
      !guardDog.decisionTree.isTrustedProvider('unknown-malicious-pkg'),
      'Should not trust unknown packages'
    );
  });

  // Test trusted scopes (Bug 3)
  await test.run('Trusted scopes detection', async () => {
    test.assert(
      guardDog.decisionTree.isTrustedProvider('@vercel/analytics'),
      'Should recognize @vercel scope as trusted'
    );
    test.assert(
      guardDog.decisionTree.isTrustedProvider('@microsoft/teams-js'),
      'Should recognize @microsoft scope as trusted'
    );
    test.assert(
      !guardDog.decisionTree.isTrustedProvider('@evil/malware'),
      'Should not trust unknown scopes'
    );
  });

  // Test @types namespace (Bug 4)
  await test.run('@types namespace matching', async () => {
    test.assert(
      guardDog.decisionTree.isTrustedProvider('@types/react'),
      'Should recognize @types/react as trusted namespace'
    );
    test.assert(
      guardDog.decisionTree.isTrustedProvider('@types/node'),
      'Should recognize @types/node as trusted namespace'
    );
  });

  // Test reputation checker
  await test.run('Reputation checker - npm (express)', async () => {
    const result = await guardDog.reputation.checkReputation('express', 'npm');
    test.assert(result, 'Should return result');
    test.assert(result.registry, 'Should have registry data');
    test.assert(result.registry.name === 'express', 'Should match package name');
    test.assert(result.signals, 'Should have signals array');
  });

  await test.run('Reputation checker - nonexistent package', async () => {
    const result = await guardDog.reputation.checkReputation(
      'this-package-definitely-does-not-exist-12345',
      'npm'
    );
    test.assert(result, 'Should return result');
    test.assert(
      result.signals.includes('PACKAGE_NOT_FOUND'),
      'Should flag missing package'
    );
  });

  // Test CVE checker initialization (Bug 1)
  await test.run('CVE checker initialized', async () => {
    test.assert(guardDog.cveChecker, 'CVE checker should be initialized');
    test.assert(guardDog.cveChecker instanceof CVEChecker, 'Should be instance of CVEChecker');
  });

  // Test pattern analyzer initialization (Bug 1)
  await test.run('Pattern analyzer initialized', async () => {
    test.assert(guardDog.patternAnalyzer, 'Pattern analyzer should be initialized');
    test.assert(guardDog.patternAnalyzer instanceof PatternAnalyzer, 'Should be instance of PatternAnalyzer');
  });

  // Test pattern analyzer detects suspicious code
  await test.run('Pattern analyzer - detect eval', async () => {
    const result = guardDog.patternAnalyzer.analyzeCode('var x = eval("malicious")');
    test.assert(result.suspicious, 'Should flag eval as suspicious');
    test.assert(result.score > 0, 'Should have non-zero score');
  });

  // Test VT scoring does not penalize when not attempted (Bug 2)
  await test.run('VT scoring - no penalty when not attempted', async () => {
    const scanResults = { success: false, maliciousVotes: 0, suspiciousVotes: 0 };
    const reputationData = { registry: { name: 'test' }, signals: [] };
    const decision = guardDog.decisionTree.evaluate(
      scanResults, reputationData, 'some-pkg', null, null, false
    );
    // Without VT penalty, a package with no signals should be SAFE
    test.assert(decision.action === 'SILENT', 'Should be SILENT when VT not attempted');
  });

  // Test VT scoring does penalize when attempted and failed (Bug 2)
  await test.run('VT scoring - penalty when attempted and failed', async () => {
    const scanResults = { success: false, maliciousVotes: 0, suspiciousVotes: 0 };
    const reputationData = { registry: { name: 'test' }, signals: [] };
    const decision = guardDog.decisionTree.evaluate(
      scanResults, reputationData, 'some-pkg', null, null, true
    );
    test.assert(
      decision.reasons.some(r => r.includes('VirusTotal scan failed')),
      'Should include VT failure reason when attempted'
    );
  });

  // Test decision tree
  await test.run('Decision tree - safe package', async () => {
    const scanResults = {
      success: true,
      found: true,
      maliciousVotes: 0,
      suspiciousVotes: 0
    };
    const reputationData = {
      registry: { name: 'test' },
      signals: []
    };
    
    const decision = guardDog.decisionTree.evaluate(
      scanResults,
      reputationData,
      'react'
    );
    
    test.assert(decision.action === 'SILENT', 'Should be SILENT for trusted package');
  });

  await test.run('Decision tree - malicious package', async () => {
    const scanResults = {
      success: true,
      found: true,
      maliciousVotes: 10,
      suspiciousVotes: 5
    };
    const reputationData = {
      registry: { name: 'malicious-pkg' },
      signals: ['SECURITY_COMPLAINTS', 'NEWLY_PUBLISHED']
    };
    
    const decision = guardDog.decisionTree.evaluate(
      scanResults,
      reputationData,
      'malicious-pkg'
    );
    
    test.assert(decision.action === 'BARK', 'Should BARK for malicious package');
    test.assert(decision.threat === 'DANGER', 'Should mark as DANGER');
    test.assert(decision.reasons.length > 0, 'Should have reasons');
  });

  await test.run('Decision tree - suspicious package', async () => {
    const scanResults = {
      success: true,
      found: false,
      maliciousVotes: 0,
      suspiciousVotes: 0
    };
    const reputationData = {
      registry: { name: 'suspicious-pkg' },
      signals: ['NEWLY_PUBLISHED', 'NO_REPOSITORY', 'LOW_STARS']
    };
    
    const decision = guardDog.decisionTree.evaluate(
      scanResults,
      reputationData,
      'suspicious-pkg'
    );
    
    test.assert(
      decision.action === 'WHINE' || decision.action === 'BARK',
      'Should WHINE or BARK for suspicious package'
    );
  });

  // Test decision formatting
  await test.run('Decision formatting', async () => {
    const decision = {
      action: 'BARK',
      threat: 'DANGER',
      confidence: 95,
      reasons: ['Test reason 1', 'Test reason 2']
    };
    
    const formatted = guardDog.decisionTree.formatDecision(decision);
    test.assert(formatted.includes('BARK'), 'Should include action');
    test.assert(formatted.includes('DANGER'), 'Should include threat');
    test.assert(formatted.includes('95%'), 'Should include confidence');
    test.assert(formatted.includes('Test reason 1'), 'Should include reasons');
  });

  // Test Telegram alert formatting
  await test.run('Telegram alert formatting', async () => {
    const decision = {
      action: 'BARK',
      threat: 'DANGER',
      confidence: 90,
      reasons: ['Malicious code detected'],
      details: { scan: { maliciousVotes: 5 } }
    };
    
    const message = guardDog.telegram.formatAlertMessage('evil-package', decision);
    test.assert(message.includes('evil-package'), 'Should include package name');
    test.assert(message.includes('DANGER'), 'Should include threat level');
    test.assert(message.includes('90%'), 'Should include confidence');
  });

  // Integration test - analyze a real package
  await test.run('Integration test - analyze trusted package', async () => {
    const result = await guardDog.analyze('lodash', 'npm');
    test.assert(result, 'Should return result');
    test.assert(result.decision, 'Should have decision');
    test.assert(result.decision.action === 'SILENT', 'Should be SILENT for lodash');
  });

  // Test weekly downloads populated (Bug 6)
  await test.run('Weekly downloads fetched for npm', async () => {
    const result = await guardDog.reputation.checkReputation('express', 'npm');
    test.assert(result.registry, 'Should have registry data');
    test.assert(
      result.registry.weeklyDownloads !== null,
      'Weekly downloads should be populated for express'
    );
    test.assert(
      result.registry.weeklyDownloads > 0,
      'Express should have positive weekly downloads'
    );
  });

  // Test scan history created (Bug 5)
  await test.run('Scan history file created', async () => {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const historyPath = join(__dirname, '../data/scan-history.json');
    test.assert(existsSync(historyPath), 'scan-history.json should exist after analysis');
  });

  // Test analyze returns CVE and pattern fields (Bug 1)
  await test.run('Analyze returns CVE and pattern results', async () => {
    const result = await guardDog.analyze('express', 'npm');
    test.assert('cveResults' in result, 'Result should include cveResults');
    test.assert('patternResults' in result, 'Result should include patternResults');
    test.assert('timestamp' in result, 'Result should include timestamp');
  });

  // Test batch analysis with mock data
  await test.run('Batch analysis', async () => {
    const packages = [
      { name: 'react', ecosystem: 'npm' },
      { name: 'lodash', ecosystem: 'npm' }
    ];
    
    const results = await guardDog.batchAnalyze(packages);
    test.assert(results.length === 2, 'Should return 2 results');
    test.assert(results[0].packageName === 'react', 'First result should be react');
    test.assert(results[1].packageName === 'lodash', 'Second result should be lodash');
  });

  // Summary
  const allPassed = test.summary();
  process.exit(allPassed ? 0 : 1);
}

// Run tests
runTests().catch(error => {
  console.error('Test runner failed:', error);
  process.exit(1);
});
