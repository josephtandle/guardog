const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('native env loader preserves repo precedence and applies user overrides', async () => {
  const { loadEnvFile } = await import('../src/env-loader.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-env-'));
  try {
    const environment = { VIRUSTOTAL_API_KEY: 'process-fixture' };
    const repo = path.join(dir, 'repo.env');
    const user = path.join(dir, 'user.env');
    fs.writeFileSync(repo, 'VIRUSTOTAL_API_KEY="repo-fixture"\nEXTRA="quoted value # preserved"\n');
    fs.writeFileSync(user, "VIRUSTOTAL_API_KEY='user-fixture'\n");
    assert.equal(loadEnvFile(repo, { environment }), true);
    assert.equal(environment.VIRUSTOTAL_API_KEY, 'process-fixture');
    assert.equal(environment.EXTRA, 'quoted value # preserved');
    loadEnvFile(user, { override: true, environment });
    assert.equal(environment.VIRUSTOTAL_API_KEY, 'user-fixture');
    assert.equal(loadEnvFile(path.join(dir, 'absent'), { environment }), false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('malformed and unreadable env files fail without leaking or partly applying values', async () => {
  const { loadEnvFile } = await import('../src/env-loader.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-bad-env-'));
  try {
    const environment = { PRESERVED: 'before' };
    for (const text of ['PRESERVED=changed\nsecret-without-assignment', 'PRESERVED="unterminated']) {
      const file = path.join(dir, 'bad.env');
      fs.writeFileSync(file, text);
      assert.throws(() => loadEnvFile(file, { override: true, environment }), error => {
        assert.equal(error.message.includes(text), false);
        return true;
      });
      assert.deepEqual(environment, { PRESERVED: 'before' });
    }
    assert.throws(() => loadEnvFile(dir, { environment }), /Cannot read/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('dependency-free copied package starts and completes quick setup', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-no-deps-'));
  try {
    const root = path.resolve(__dirname, '..');
    fs.cpSync(path.join(root, 'src'), path.join(dir, 'src'), { recursive: true });
    fs.cpSync(path.join(root, 'config'), path.join(dir, 'config'), { recursive: true });
    fs.copyFileSync(path.join(root, 'package.json'), path.join(dir, 'package.json'));
    for (const args of [['--version'], ['setup', '--quick']]) {
      const result = spawnSync(process.execPath, [path.join(dir, 'src/index.js'), ...args], {
        encoding: 'utf8', env: { ...process.env, GUARDOG_HOME: path.join(dir, 'state') }
      });
      assert.equal(result.status, 0, result.stderr);
    }
    assert.equal(fs.existsSync(path.join(dir, 'state/config.json')), true);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
