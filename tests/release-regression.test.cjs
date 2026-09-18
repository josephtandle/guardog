const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

// Real packed installation on each platform, including paths containing spaces.
test('packed release installs and runs without workspace helpers', () => {
  const root = path.resolve(__dirname, '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard dog packed '));
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, 'Run the release suite with npm test so npm-cli.js is known on Windows');
  const run = (args, opts = {}) => spawnSync(process.execPath, args, { cwd: dir, encoding: 'utf8', ...opts });
  try {
    const pack = run([npmCli, 'pack', '--json', '--ignore-scripts', '--pack-destination', dir], { cwd: root });
    assert.equal(pack.status, 0, pack.stderr);
    const artifact = JSON.parse(pack.stdout)[0];
    assert.equal(artifact.files.some(f => /telegram/i.test(f.path)), false);
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ private: true }));
    const install = run([npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund', path.join(dir, artifact.filename)]);
    assert.equal(install.status, 0, install.stderr);
    const cli = path.join(dir, 'node_modules', 'guard-dog', 'src', 'index.js');
    const env = { ...process.env, GUARDOG_HOME: path.join(dir, 'state'), VIRUSTOTAL_API_KEY: '' };
    const source = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    assert.equal(run([cli, '--version'], { env }).stdout.trim(), source.version);
    const setup = run([cli, 'setup', '--quick'], { env });
    assert.equal(setup.status, 0, setup.stderr);
    assert.equal(fs.existsSync(path.join(env.GUARDOG_HOME, 'config.json')), true);
    const doctor = run([cli, 'doctor'], { env });
    assert.ok([0, 2].includes(doctor.status), doctor.stderr);
    assert.match(doctor.stdout, /doctor/i);
    for (const alias of ['guardog', 'guarddog', 'guard-dog']) {
      assert.ok(fs.existsSync(path.join(dir, 'node_modules', '.bin', alias + (process.platform === 'win32' ? '.cmd' : ''))));
    }
    const blocked = run([cli, 'install', 'pip', '-r', 'requirements.txt'], { env });
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /not supported|cannot safely/i);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
