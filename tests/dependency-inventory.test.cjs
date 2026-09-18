const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
async function fixture(files, callback) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-inventory-'));
  try {
    for (const [name, value] of Object.entries(files)) {
      const file = path.join(dir, name);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify(value));
    }
    const { collectDependencies } = await import('../src/dependency-inventory.js');
    await callback(collectDependencies(path.join(dir, 'package.json')), dir);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
test('audits exact locked transitive versions instead of latest', async () => {
  await fixture({ 'package.json': { dependencies: { app: '^1.0.0' } }, 'package-lock.json': {
    lockfileVersion: 3, packages: { '': {}, 'node_modules/app': { version: '1.0.0' },
      'node_modules/app/node_modules/node-ipc': { version: '10.1.1' } }
  } }, result => {
    assert.equal(result.complete, true);
    assert.deepEqual(result.packages.map(p => [p.name, p.version]), [['app', '1.0.0'], ['node-ipc', '10.1.1']]);
  });
});
test('v1 preserves different transitive versions and shrinkwrap precedence', async () => {
  await fixture({ 'package.json': { dependencies: { app: '*' } },
    'package-lock.json': { lockfileVersion: 3, packages: { 'node_modules/app': { version: '9.0.0' } } },
    'npm-shrinkwrap.json': { lockfileVersion: 1, dependencies: { app: { version: '1.0.0', dependencies: { app: { version: '2.0.0' } } } } }
  }, result => {
    assert.equal(result.complete, true);
    assert.deepEqual(result.packages.map(p => p.version), ['1.0.0', '2.0.0']);
  });
});
test('installed metadata overrides lock and aliases use actual names', async () => {
  await fixture({ 'package.json': { dependencies: { alias: 'npm:@scope/pkg@1.0.0' } },
    'package-lock.json': { lockfileVersion: 2, packages: { 'node_modules/alias': { name: '@scope/pkg', version: '1.0.0' } } },
    'node_modules/alias/package.json': { name: '@scope/pkg', version: '1.1.0' }
  }, result => {
    assert.equal(result.complete, true);
    assert.equal(result.packages[0].name, '@scope/pkg');
    assert.equal(result.packages[0].version, '1.1.0');
    assert.equal(result.packages[0].provenance, 'installed');
  });
});
test('unresolved manifest ranges are incomplete and never latest', async () => {
  await fixture({ 'package.json': { dependencies: { app: '^1.0.0' } } }, result => {
    assert.equal(result.complete, false);
    assert.equal(result.packages.length, 0);
  });
});
test('outside project lock paths cannot supply versions', async () => {
  await fixture({ 'package.json': {}, 'package-lock.json': { lockfileVersion: 3, packages: {
    '../node_modules/escape': { version: '1.0.0' }, 'node_modules/link': { link: true, resolved: '../../escape' }
  } } }, result => {
    assert.equal(result.complete, false);
    assert.equal(result.packages.length, 0);
  });
});
test('workspace links do not become registry packages; transitive entries still scan', async () => {
  await fixture({ 'package.json': { dependencies: { local: 'workspace:*' } }, 'package-lock.json': { lockfileVersion: 3, packages: {
    'node_modules/local': { link: true, resolved: 'packages/local' },
    'packages/local': { name: 'local', version: '1.0.0' },
    'packages/local/node_modules/@scope/leaf': { version: '2.0.0' }
  } } }, result => {
    assert.equal(result.complete, true);
    assert.deepEqual(result.packages.map(p => p.name), ['@scope/leaf']);
  });
});
test('CLI returns machine-readable incomplete status for unresolved dependencies', async () => {
  await fixture({ 'package.json': { dependencies: { missing: '*' } } }, (_result, dir) => {
    const { spawnSync } = require('node:child_process');
    const run = spawnSync(process.execPath, [path.resolve(__dirname, '../bin/scan-deps.js'), path.join(dir, 'package.json'), '--json'], { encoding: 'utf8' });
    assert.equal(run.status, 2);
    const report = JSON.parse(run.stdout);
    assert.equal(report.status, 'incomplete');
    assert.equal(report.dependencyCount, 0);
  });
});
