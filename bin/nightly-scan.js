#!/usr/bin/env node
import { existsSync, readdirSync, realpathSync, statSync, writeFileSync, renameSync, readFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { ensureGuardogHome, guardogHome, packageRoot } from '../src/paths.js';
import { loadUserConfig } from '../src/setup.js';
import { checkHealth } from '../src/health.js';

const skipDirs = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.venv', 'venv']);

export function runNightly(options = {}) {
  ensureGuardogHome();
  const lockPath = join(guardogHome(), 'data', 'nightly.lock');
  const token = JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() });
  try {
    if (existsSync(lockPath)) {
      const original = readFileSync(lockPath, 'utf8');
      const { pid } = JSON.parse(original);
      if (Number.isInteger(pid) && pid > 0) {
        try { process.kill(pid, 0); }
        catch (error) { if (error.code === 'ESRCH' && readFileSync(lockPath, 'utf8') === original) unlinkSync(lockPath); }
      }
    }
    const descriptor = openSync(lockPath, 'wx', 0o600);
    try { writeFileSync(descriptor, token); } finally { closeSync(descriptor); }
  } catch {
    return { taskClass: 'security_scan', status: 'incomplete', exitCode: 2, dependencyCount: 0, dangerousCount: 0, issues: ['Another nightly run owns the lock, or the lock cannot be verified. No overlapping scan was started.'] };
  }
  try { return performNightly(options); }
  finally { if (existsSync(lockPath) && readFileSync(lockPath, 'utf8') === token) unlinkSync(lockPath); }
}

function performNightly(options) {
  const config = options.config || loadUserConfig();
  const deadline = Date.now() + (options.timeoutMs ?? 3600000);
  const roots = options.roots || (process.env.GUARDOG_WORKSPACE ? [resolve(process.env.GUARDOG_WORKSPACE)] : config.scanRoots || []);
  const run = options.run || spawnSync;
  const receipt = { taskClass: 'security_scan', startedAt: new Date().toISOString(), status: 'incomplete', roots, projectsScanned: 0, dependencyCount: 0, dangerousCount: 0, issues: [] };
  const manifests = new Set();
  const visited = new Set();
  const maxDepth = Number(process.env.GUARDOG_MAX_DEPTH || 4);
  function discover(dir, depth = 0) {
    if (Date.now() >= deadline) { receipt.issues.push('Nightly discovery time budget exhausted.'); return; }
    if (depth > maxDepth) { receipt.issues.push('Discovery depth exceeded: ' + dir); return; }
    try {
      const identity = realpathSync(dir);
      if (identity === realpathSync(guardogHome()) || visited.has(identity)) return;
      visited.add(identity);
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory() && !skipDirs.has(entry.name) && !entry.name.startsWith('.')) discover(full, depth + 1);
        else if (entry.isFile() && entry.name === 'package.json') manifests.add(full);
      }
    } catch (error) { receipt.issues.push('Cannot read ' + dir + ': ' + (error.code || error.message)); }
  }
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 30) receipt.issues.push('GUARDOG_MAX_DEPTH must be an integer from 0 to 30.');
  else for (const root of roots) {
    if (typeof root !== 'string' || !existsSync(root) || !statSync(root).isDirectory()) receipt.issues.push('Scan root is unavailable: ' + root);
    else discover(root);
  }
  if (roots.length === 0) receipt.issues.push('No scan roots configured. Run guardog setup or set GUARDOG_WORKSPACE.');
  for (const manifest of manifests) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { receipt.issues.push('Nightly scan time budget exhausted.'); break; }
    const result = run(process.execPath, [join(packageRoot(), 'bin', 'scan-deps.js'), manifest, '--json'], { encoding: 'utf8', timeout: Math.min(300000, remaining), maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    receipt.projectsScanned++;
    try {
      const summary = JSON.parse(result.stdout);
      if (!Number.isInteger(summary.dependencyCount) || summary.dependencyCount < 0 || !['complete', 'dangerous', 'incomplete'].includes(summary.status)) throw new Error('invalid scan summary');
      receipt.dependencyCount += summary.dependencyCount;
      receipt.dangerousCount += Number(summary.dangerousCount) || 0;
      if (summary.status === 'dangerous' && !summary.dangerousCount) receipt.dangerousCount++;
      const expectedExit = { complete: 0, dangerous: 1, incomplete: 2 }[summary.status];
      if (summary.status === 'incomplete' || result.status !== expectedExit) receipt.issues.push('Incomplete or inconsistent scan: ' + manifest);
      for (const issue of summary.issues || []) receipt.issues.push(manifest + ': ' + (typeof issue === 'string' ? issue : JSON.stringify(issue)));
    } catch { receipt.issues.push('Scan failed for ' + manifest + ': ' + (result.error?.message || result.stderr || 'missing scan summary')); }
  }
  if (receipt.dependencyCount === 0) receipt.issues.push('No installed dependencies were scanned.');
  receipt.status = receipt.issues.length ? 'incomplete' : receipt.dangerousCount > 0 ? 'dangerous' : 'complete';
  receipt.finishedAt = new Date().toISOString();
  receipt.exitCode = receipt.status === 'incomplete' ? 2 : receipt.status === 'dangerous' ? 1 : 0;
  const receiptPath = join(guardogHome(), 'data', 'last-nightly.json');
  const temporary = receiptPath + '.' + process.pid + '.tmp';
  writeFileSync(temporary, JSON.stringify(receipt, null, 2), { mode: 0o600 });
  renameSync(temporary, receiptPath);
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    // Bounded repair is limited to owned local state and prior schedule consent.
    checkHealth({ repair: true });
    const receipt = runNightly();
    console.log(JSON.stringify(receipt, null, 2));
    process.exitCode = receipt.exitCode;
  } catch (error) {
    console.error('Guardog nightly scan incomplete: ' + error.message);
    process.exitCode = 2;
  }
}
