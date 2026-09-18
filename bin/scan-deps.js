#!/usr/bin/env node
/** Audit exact installed/locked npm dependencies. Exit 0 complete, 1 danger, 2 incomplete. */
import { resolve } from 'node:path';
import { collectDependencies } from '../src/dependency-inventory.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const manifest = args[0];
const log = console.log.bind(console);
const errorLog = console.error.bind(console);
async function main() {
  if (!manifest || manifest.startsWith('--')) throw new Error('Usage: guard-dog-scan <package.json> [--json] [--changed-only <old-package.json>]');
  const inventory = collectDependencies(resolve(manifest));
  // Manifest changes can alter transitive resolution, so legacy changed-only callers
  // receive a full resolved inventory audit rather than skipping vulnerable leaves.
  if (!json && args.includes('--changed-only')) log('Auditing the full resolved dependency inventory, including transitive changes.');
  let results = [];
  if (inventory.packages.length > 0) {
    if (json) { console.log = () => {}; console.error = () => {}; console.warn = () => {}; }
    const { GuardDog } = await import('../src/index.js');
    results = await new GuardDog().batchAnalyze(inventory.packages);
  }
  const dangerousCount = results.filter(result => result.decision?.action === 'BARK').length;
  const incomplete = !inventory.complete || results.some(result => result.decision?.coverage === 'incomplete' || result.cveResults?.status === 'unavailable');
  const status = dangerousCount ? 'dangerous' : incomplete ? 'incomplete' : 'complete';
  const summary = { status, dependencyCount: inventory.packages.length, dangerousCount, issues: inventory.issues };
  if (json) log(JSON.stringify(summary));
  else {
    log(`Guard Dog: ${summary.dependencyCount} exact dependency versions audited; ${status}.`);
    inventory.issues.forEach(issue => errorLog(`Incomplete coverage: ${issue}`));
  }
  process.exitCode = dangerousCount ? 1 : incomplete ? 2 : 0;
}
main().catch(error => {
  if (json) log(JSON.stringify({ status: 'incomplete', dependencyCount: 0, dangerousCount: 0, issues: [error.message] }));
  else errorLog(error.message);
  process.exitCode = 2;
});
