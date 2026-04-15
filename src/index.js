#!/usr/bin/env node
/**
 * Guard Dog - Package Security Scanner
 * Main orchestrator that coordinates all modules
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

import { VirusTotalScanner } from './virustotal-scanner.js';
import { ReputationChecker } from './reputation-checker.js';
import { CVEChecker } from './cve-checker.js';
import { PatternAnalyzer } from './pattern-analyzer.js';
import { DecisionTree } from './decision-tree.js';
import { TelegramAlert } from './telegram-alert.js';

// Load environment variables
dotenv.config({ path: join(dirname(fileURLToPath(import.meta.url)), '../.env') });

export class GuardDog {
  constructor() {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    
    // Load configurations
    this.config = JSON.parse(
      readFileSync(join(__dirname, '../config/config.json'), 'utf-8')
    );
    
    this.trustedProviders = JSON.parse(
      readFileSync(join(__dirname, '../config/trusted-providers.json'), 'utf-8')
    );

    // Initialize modules
    try {
      this.scanner = new VirusTotalScanner(this.config);
    } catch (error) {
      console.warn('⚠️ VirusTotal scanner disabled:', error.message);
      this.scanner = null;
    }

    this.reputation = new ReputationChecker(this.config);
    this.cveChecker = new CVEChecker(this.config);
    this.patternAnalyzer = new PatternAnalyzer(this.config);
    this.decisionTree = new DecisionTree(this.config, this.trustedProviders);
    this.telegram = new TelegramAlert(this.config);

    // Ensure data directory exists for scan history
    this.dataDir = join(dirname(fileURLToPath(import.meta.url)), '../data');
    if (!existsSync(this.dataDir)) {
      mkdirSync(this.dataDir, { recursive: true });
    }
  }

  /**
   * Scan a package and determine threat level
   * @param {string} packageName - Package name
   * @param {string} ecosystem - 'npm' or 'pypi'
   * @param {string} target - Optional URL or hash to scan
   * @returns {Promise<Object>} Analysis results
   */
  async analyze(packageName, ecosystem = 'npm', target = null) {
    console.log(`\n🐕 Guard Dog analyzing: ${packageName} (${ecosystem})`);
    console.log('─'.repeat(60));

    const startTime = Date.now();
    let scanResults = { success: false, maliciousVotes: 0, suspiciousVotes: 0 };
    let reputationData = null;
    let cveResults = null;
    let patternResults = null;
    let vtAttempted = false;

    // Step 1: Reputation check
    console.log('📊 Checking reputation...');
    try {
      reputationData = await this.reputation.checkReputation(packageName, ecosystem);
      console.log(`✓ Reputation check complete (${reputationData.signals.length} signals)`);
    } catch (error) {
      console.error('✗ Reputation check failed:', error.message);
    }

    // Step 2: VirusTotal scan (if available and target provided)
    if (this.scanner && target) {
      vtAttempted = true;
      console.log('🔍 Scanning with VirusTotal...');
      try {
        scanResults = await this.scanner.scan(target);
        if (scanResults.success) {
          console.log(`✓ VirusTotal scan complete (${scanResults.totalEngines} engines)`);
        } else {
          console.log('✗ VirusTotal scan failed:', scanResults.error);
        }
      } catch (error) {
        console.error('✗ VirusTotal scan failed:', error.message);
      }
    } else if (!this.scanner) {
      console.log('⚠️  VirusTotal scan skipped (no API key)');
    } else {
      console.log('⚠️  VirusTotal scan skipped (no target URL/hash)');
    }

    // Step 3: CVE check
    console.log('🔐 Checking CVE databases...');
    try {
      const version = reputationData?.registry?.version || null;
      cveResults = await this.cveChecker.checkCVEs(packageName, ecosystem, version);
      const cveCount = cveResults.vulnerabilities?.length || 0;
      console.log(`✓ CVE check complete (${cveCount} vulnerabilities found)`);
    } catch (error) {
      console.error('✗ CVE check failed:', error.message);
    }

    // Step 4: Pattern analysis (analyze install scripts / main entry if available from registry)
    console.log('🔎 Analyzing code patterns...');
    try {
      // Use registry metadata as a lightweight code signal source
      const codeSnippets = {};
      if (reputationData?.registry?.description) {
        codeSnippets['description'] = reputationData.registry.description;
      }
      patternResults = this.patternAnalyzer.analyzeFiles(codeSnippets);
      console.log(`✓ Pattern analysis complete (score: ${patternResults.totalScore})`);
    } catch (error) {
      console.error('✗ Pattern analysis failed:', error.message);
    }

    // Step 5: Decision tree evaluation
    console.log('🎯 Evaluating threat level...');
    const decision = this.decisionTree.evaluate(
      scanResults, reputationData, packageName,
      cveResults, patternResults ? { suspicious: patternResults.suspiciousFiles > 0, score: patternResults.totalScore, severity: patternResults.combinedSeverity } : null,
      vtAttempted
    );

    // Step 6: Alert if dangerous
    if (decision.action === 'BARK') {
      console.log('🚨 DANGER DETECTED - Sending Telegram alert...');
      const alertSent = await this.telegram.sendDangerAlert(packageName, decision);
      if (alertSent) {
        console.log('✓ Telegram alert sent');
      } else {
        console.log('✗ Telegram alert failed');
      }
    }

    // Print results
    console.log('\n' + this.decisionTree.formatDecision(decision));

    // Suggest code-level review for flagged packages
    if (decision.action === 'BARK' || decision.action === 'WHINE') {
      console.log('\n💡 Code-level review: run /gstack-cso in Claude Code, or: bash bin/run-cso.sh <affected-path>');
    }

    const duration = Date.now() - startTime;
    console.log(`⏱️  Analysis completed in ${duration}ms`);
    console.log('─'.repeat(60));

    const result = {
      packageName,
      ecosystem,
      decision,
      scanResults,
      reputationData,
      cveResults,
      patternResults,
      duration,
      timestamp: new Date().toISOString()
    };

    // Save to scan history
    this.saveScanHistory(result);

    return result;
  }

  /**
   * Save scan result to history file (keeps last 500 entries)
   * @param {Object} result - Scan result
   */
  saveScanHistory(result) {
    try {
      const historyPath = join(this.dataDir, 'scan-history.json');
      let history = [];
      if (existsSync(historyPath)) {
        history = JSON.parse(readFileSync(historyPath, 'utf-8'));
      }
      history.push({
        packageName: result.packageName,
        ecosystem: result.ecosystem,
        action: result.decision.action,
        threat: result.decision.threat,
        confidence: result.decision.confidence,
        reasons: result.decision.reasons,
        cveCount: result.cveResults?.vulnerabilities?.length || 0,
        patternScore: result.patternResults?.totalScore || 0,
        duration: result.duration,
        timestamp: result.timestamp
      });
      // Keep last 500 entries
      if (history.length > 500) {
        history = history.slice(-500);
      }
      writeFileSync(historyPath, JSON.stringify(history, null, 2));
    } catch (error) {
      console.error('⚠️  Failed to save scan history:', error.message);
    }
  }

  /**
   * Batch analyze multiple packages
   * @param {Array<Object>} packages - Array of {name, ecosystem, target?}
   * @returns {Promise<Array>} Results for all packages
   */
  async batchAnalyze(packages) {
    console.log(`\n🐕 Guard Dog batch analysis: ${packages.length} packages\n`);
    
    const results = [];
    for (const pkg of packages) {
      const result = await this.analyze(pkg.name, pkg.ecosystem, pkg.target);
      results.push(result);
      
      // Small delay between requests to avoid rate limits
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Summary
    const dangerous = results.filter(r => r.decision.action === 'BARK').length;
    const suspicious = results.filter(r => r.decision.action === 'WHINE').length;
    const safe = results.filter(r => r.decision.action === 'SILENT').length;

    console.log('\n📊 BATCH ANALYSIS SUMMARY');
    console.log('─'.repeat(60));
    console.log(`🚨 Dangerous:  ${dangerous}`);
    console.log(`⚠️  Suspicious: ${suspicious}`);
    console.log(`✅ Safe:       ${safe}`);
    console.log(`📦 Total:      ${results.length}`);
    console.log('─'.repeat(60));

    return results;
  }

  /**
   * Test Guard Dog setup
   * @returns {Promise<Object>} Test results
   */
  async test() {
    console.log('\n🐕 Guard Dog System Test\n');
    console.log('─'.repeat(60));

    const tests = {
      config: false,
      virustotal: false,
      reputation: false,
      telegram: false
    };

    // Test config
    console.log('📋 Testing configuration...');
    tests.config = !!this.config && !!this.trustedProviders;
    console.log(tests.config ? '✓ Config loaded' : '✗ Config failed');

    // Test VirusTotal
    console.log('🔍 Testing VirusTotal connection...');
    if (this.scanner) {
      try {
        await this.scanner.getFileReport('test');
        tests.virustotal = true;
        console.log('✓ VirusTotal API key valid');
      } catch (error) {
        console.log('✗ VirusTotal test failed:', error.message);
      }
    } else {
      console.log('⚠️  VirusTotal scanner not initialized');
    }

    // Test reputation checker
    console.log('📊 Testing reputation checker...');
    try {
      const testResult = await this.reputation.checkReputation('express', 'npm');
      tests.reputation = testResult && testResult.registry;
      console.log(tests.reputation ? '✓ Reputation checker working' : '✗ Reputation check failed');
    } catch (error) {
      console.log('✗ Reputation test failed:', error.message);
    }

    // Test Telegram
    console.log('📱 Testing Telegram connection...');
    tests.telegram = await this.telegram.testConnection();

    console.log('─'.repeat(60));
    const passed = Object.values(tests).filter(Boolean).length;
    console.log(`\n✅ ${passed}/${Object.keys(tests).length} tests passed\n`);

    return tests;
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const command = args[0];

  const guardDog = new GuardDog();

  if (command === 'test') {
    // Run system test
    await guardDog.test();
  } else if (command === 'analyze') {
    // Analyze single package
    const packageName = args[1];
    const ecosystem = args[2] || 'npm';
    const target = args[3];

    if (!packageName) {
      console.error('Usage: node index.js analyze <package-name> [ecosystem] [url/hash]');
      process.exit(1);
    }

    await guardDog.analyze(packageName, ecosystem, target);
  } else if (command === 'batch') {
    // Batch analyze from JSON file
    const filePath = args[1];
    if (!filePath) {
      console.error('Usage: node index.js batch <json-file>');
      process.exit(1);
    }

    const packages = JSON.parse(readFileSync(filePath, 'utf-8'));
    await guardDog.batchAnalyze(packages);
  } else {
    console.log('Guard Dog - Package Security Scanner');
    console.log('');
    console.log('Usage:');
    console.log('  node index.js test                           - Run system test');
    console.log('  node index.js analyze <pkg> [eco] [target]   - Analyze single package');
    console.log('  node index.js batch <json-file>              - Batch analyze packages');
    console.log('');
    console.log('Examples:');
    console.log('  node index.js test');
    console.log('  node index.js analyze lodash npm');
    console.log('  node index.js analyze django pypi');
    console.log('  node index.js batch packages.json');
  }
}
