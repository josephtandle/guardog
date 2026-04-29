#!/usr/bin/env node
/**
 * Guard Dog - Package Security Scanner
 * Main orchestrator that coordinates all modules
 */

import { readFileSync, writeFileSync, existsSync, realpathSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import { spawnSync } from 'child_process';
import dotenv from 'dotenv';

import { VirusTotalScanner } from './virustotal-scanner.js';
import { ReputationChecker } from './reputation-checker.js';
import { CVEChecker } from './cve-checker.js';
import { PatternAnalyzer } from './pattern-analyzer.js';
import { DecisionTree } from './decision-tree.js';
import { TelegramAlert } from './telegram-alert.js';
import { ensureGuardogHome, guardogDataDir, guardogEnvPath, packageRoot } from './paths.js';
import {
  installGitHook,
  installNightlySchedule,
  loadUserConfig,
  printDoctor,
  removeGitHook,
  removeNightlySchedule,
  runSetup,
  saveUserConfig
} from './setup.js';

// Load environment variables
dotenv.config({ path: join(dirname(fileURLToPath(import.meta.url)), '../.env') });
dotenv.config({ path: guardogEnvPath(), override: true });

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

    // Keep runtime state out of the installed package so global installs work
    // on macOS, Windows, Linux, and read-only npm package directories.
    ensureGuardogHome();
    this.dataDir = guardogDataDir();
  }

  /**
   * Load history from disk and repair simple malformed-array cases in place.
   * This keeps GuardDog writing durable evidence even if a previous run left
   * a trailing extra bracket in the history file.
   * @param {string} historyPath
   * @returns {Array<Object>}
   */
  loadScanHistory(historyPath) {
    if (!existsSync(historyPath)) return [];

    const raw = readFileSync(historyPath, 'utf-8').trim();
    if (!raw) return [];

    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      const repairedCandidates = [
        raw.replace(/\]\s*\]+$/s, ']'),
        raw.slice(0, raw.lastIndexOf(']') + 1),
      ].filter(Boolean);

      for (const candidate of repairedCandidates) {
        try {
          const parsed = JSON.parse(candidate);
          if (Array.isArray(parsed)) {
            writeFileSync(historyPath, JSON.stringify(parsed, null, 2));
            return parsed;
          }
        } catch {
          // keep trying candidates
        }
      }

      return [];
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
      let history = this.loadScanHistory(historyPath);
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

function usage() {
  console.log('Guardog - Package Security Scanner');
  console.log('');
  console.log('Usage:');
  console.log('  guardog setup                         - Run first-time setup wizard');
  console.log('  guardog doctor                        - Check local configuration');
  console.log('  guardog test                          - Run system test');
  console.log('  guardog analyze <pkg> [eco] [target]  - Analyze one package');
  console.log('  guardog batch <json-file>             - Batch analyze packages');
  console.log('  guardog install [npm install args]    - Scan, then run npm install');
  console.log('  guardog nightly                       - Scan package.json files under $HOME');
  console.log('  guardog updates enable|disable|status - Manage midnight scans');
  console.log('  guardog hooks enable|disable|status   - Manage git dependency hook');
}

function packageSpecsFromInstallArgs(args) {
  return args.filter(arg => {
    if (!arg || arg.startsWith('-')) return false;
    if (arg === 'install' || arg === 'i' || arg === 'add') return false;
    if (arg.includes('/') && !arg.startsWith('@')) return false;
    return !arg.includes('=');
  });
}

async function guardedInstall(args) {
  const packages = packageSpecsFromInstallArgs(args).map(spec => {
    const withoutAlias = spec.includes('@npm:') ? spec.split('@npm:').pop() : spec;
    const atIndex = withoutAlias.startsWith('@') ? withoutAlias.indexOf('@', 1) : withoutAlias.indexOf('@');
    const name = atIndex > 0 ? withoutAlias.slice(0, atIndex) : withoutAlias;
    return { name, ecosystem: 'npm' };
  });

  const guardDog = new GuardDog();
  if (packages.length > 0) {
    console.log(`Guardog pre-install scan: ${packages.map(p => p.name).join(', ')}`);
    const results = await guardDog.batchAnalyze(packages);
    const dangerous = results.filter(r => r.decision.action === 'BARK');
    if (dangerous.length > 0) {
      console.error('\nGuardog blocked install because dangerous package(s) were found.');
      process.exit(1);
    }
  } else {
    const pkgPath = resolve(process.cwd(), 'package.json');
    if (existsSync(pkgPath)) {
      const scan = spawnSync(process.execPath, [join(packageRoot(), 'bin', 'scan-deps.js'), pkgPath], { stdio: 'inherit' });
      if (scan.status !== 0) {
        console.error('\nGuardog blocked install because dependency scan failed.');
        process.exit(scan.status || 1);
      }
    } else {
      console.log('No package names or package.json found; running npm install without a Guardog package scan.');
    }
  }

  const npmArgs = args.length > 0 && ['install', 'i', 'add'].includes(args[0]) ? args : ['install', ...args];
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const result = spawnSync(npmCmd, npmArgs, { stdio: 'inherit', shell: false });
  process.exit(result.status ?? 1);
}

function updatesCommand(action) {
  const config = loadUserConfig();
  if (action === 'enable') {
    const result = installNightlySchedule();
    config.nightlyUpdates = result.ok;
    saveUserConfig(config);
    console.log(result.message);
  } else if (action === 'disable') {
    const result = removeNightlySchedule();
    config.nightlyUpdates = false;
    saveUserConfig(config);
    console.log(result.message);
  } else {
    console.log(`Nightly updates: ${config.nightlyUpdates ? 'enabled' : 'disabled'}`);
    console.log('Default is disabled. Enable with `guardog updates enable`.');
  }
}

function hooksCommand(action) {
  const config = loadUserConfig();
  if (action === 'enable') {
    const result = installGitHook();
    config.gitPreCommitHook = result.ok;
    saveUserConfig(config);
    console.log(result.message);
  } else if (action === 'disable') {
    const result = removeGitHook();
    config.gitPreCommitHook = false;
    saveUserConfig(config);
    console.log(result.message);
  } else {
    console.log(`Git pre-commit hook: ${config.gitPreCommitHook ? 'enabled' : 'disabled'}`);
    console.log('Guarded installs: use `guardog install <package>` before dependency installs.');
  }
}

// CLI interface
const invokedPath = process.argv[1] ? realpathSync(resolve(process.argv[1])) : '';
if (fileURLToPath(import.meta.url) === invokedPath) {
  const args = process.argv.slice(2);
  const command = args[0];

  if (command === 'setup') {
    await runSetup();
  } else if (command === 'doctor') {
    printDoctor();
  } else if (command === 'updates') {
    updatesCommand(args[1] || 'status');
  } else if (command === 'hooks') {
    hooksCommand(args[1] || 'status');
  } else if (command === 'install') {
    await guardedInstall(args.slice(1));
  } else if (command === 'nightly') {
    const result = spawnSync(process.execPath, [join(packageRoot(), 'bin', 'nightly-scan.js')], { stdio: 'inherit' });
    process.exit(result.status ?? 1);
  } else if (command === 'test') {
    // Run system test
    const guardDog = new GuardDog();
    await guardDog.test();
  } else if (command === 'analyze') {
    // Analyze single package
    const guardDog = new GuardDog();
    const packageName = args[1];
    const ecosystem = args[2] || 'npm';
    const target = args[3];

    if (!packageName) {
      console.error('Usage: guardog analyze <package-name> [ecosystem] [url/hash]');
      process.exit(1);
    }

    await guardDog.analyze(packageName, ecosystem, target);
  } else if (command === 'batch') {
    // Batch analyze from JSON file
    const guardDog = new GuardDog();
    const filePath = args[1];
    if (!filePath) {
      console.error('Usage: guardog batch <json-file>');
      process.exit(1);
    }

    const packages = JSON.parse(readFileSync(filePath, 'utf-8'));
    await guardDog.batchAnalyze(packages);
  } else {
    usage();
  }
}
