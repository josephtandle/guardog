#!/usr/bin/env node
import { existsSync, readdirSync, statSync } from 'fs';
import { join, resolve } from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import os from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const workspace = resolve(process.env.GUARDOG_WORKSPACE || os.homedir());
const maxDepth = Number(process.env.GUARDOG_MAX_DEPTH || 4);
const skipDirs = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage']);

function findPackageJson(dir, depth = 0, found = []) {
  if (depth > maxDepth) return found;
  let entries = [];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return found;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!skipDirs.has(entry.name)) {
        findPackageJson(join(dir, entry.name), depth + 1, found);
      }
    } else if (entry.isFile() && entry.name === 'package.json') {
      found.push(join(dir, entry.name));
    }
  }
  return found;
}

console.log(`===== Guardog Nightly Scan: ${new Date().toISOString()} =====`);
console.log(`Workspace: ${workspace}`);

if (!existsSync(workspace) || !statSync(workspace).isDirectory()) {
  console.error(`Workspace not found: ${workspace}`);
  process.exit(1);
}

const packages = findPackageJson(workspace);
let dangerous = 0;

for (const pkg of packages) {
  console.log(`\n--- Scanning: ${pkg} ---`);
  const result = spawnSync(process.execPath, [join(root, 'bin', 'scan-deps.js'), pkg], { stdio: 'inherit' });
  if (result.status !== 0) {
    dangerous += 1;
  }
}

console.log('\n===== Nightly Scan Complete =====');
console.log(`Projects scanned: ${packages.length}`);
console.log(`Dangerous projects: ${dangerous}`);
process.exit(dangerous > 0 ? 1 : 0);
