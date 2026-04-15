#!/usr/bin/env node
/**
 * Guard Dog Dependency Scanner
 * Reads a project's package.json and scans all dependencies.
 * Used by: cron, npm hooks, git hooks, Mission Control.
 *
 * Usage:
 *   node scan-deps.js <path-to-package.json> [--changed-only <old-package.json>]
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// Guard Dog lives one level up from bin/
const __dirname = dirname(fileURLToPath(import.meta.url));
const guardDogRoot = resolve(__dirname, '..');

// Dynamic import so we can resolve relative to guard-dog
const { GuardDog } = await import(resolve(guardDogRoot, 'src/index.js'));

const args = process.argv.slice(2);
const pkgPath = args[0];
const changedOnlyFlag = args.indexOf('--changed-only');
const oldPkgPath = changedOnlyFlag !== -1 ? args[changedOnlyFlag + 1] : null;

if (!pkgPath) {
  console.error('Usage: scan-deps.js <package.json> [--changed-only <old-package.json>]');
  process.exit(1);
}

const fullPath = resolve(pkgPath);
if (!existsSync(fullPath)) {
  console.error(`File not found: ${fullPath}`);
  process.exit(1);
}

const pkg = JSON.parse(readFileSync(fullPath, 'utf-8'));
const allDeps = {
  ...pkg.dependencies,
  ...pkg.devDependencies
};

let depsToScan = Object.keys(allDeps);

// If --changed-only, only scan new or changed dependencies
if (oldPkgPath && existsSync(resolve(oldPkgPath))) {
  const oldPkg = JSON.parse(readFileSync(resolve(oldPkgPath), 'utf-8'));
  const oldDeps = {
    ...oldPkg.dependencies,
    ...oldPkg.devDependencies
  };
  depsToScan = depsToScan.filter(dep => {
    // New dep or version changed
    return !oldDeps[dep] || oldDeps[dep] !== allDeps[dep];
  });
}

if (depsToScan.length === 0) {
  console.log('🐕 Guard Dog: No dependencies to scan.');
  process.exit(0);
}

console.log(`🐕 Guard Dog: Scanning ${depsToScan.length} dependencies from ${fullPath}`);

const guardDog = new GuardDog();
const packages = depsToScan.map(name => ({ name, ecosystem: 'npm' }));
const results = await guardDog.batchAnalyze(packages);

// Exit with non-zero if any BARK (danger) found
const dangerous = results.filter(r => r.decision.action === 'BARK');
if (dangerous.length > 0) {
  console.error(`\n🚨 Guard Dog found ${dangerous.length} DANGEROUS package(s)!`);
  dangerous.forEach(r => {
    console.error(`  - ${r.packageName}: ${r.decision.reasons.join(', ')}`);
  });
  process.exit(1);
}

process.exit(0);
