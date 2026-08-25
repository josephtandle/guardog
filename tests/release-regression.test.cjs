"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const repoRoot = path.resolve(__dirname, "..");

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    ...options,
  });
}

test("packed Guardog starts without workspace-only helpers", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardog-packed-"));

  try {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({ name: "guardog-release-test", version: "1.0.0", private: true })
    );

    const packed = run("npm", ["pack", "--json", "--pack-destination", tempDir]);
    assert.equal(packed.status, 0, packed.stderr || packed.stdout);
    const [{ filename, files }] = JSON.parse(packed.stdout);

    assert.equal(
      files.some(({ path: filePath }) => /telegram/i.test(filePath)),
      false,
      "the public package must not contain Telegram modules"
    );

    const tarball = path.join(tempDir, filename);
    const installed = run(
      "npm",
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
      { cwd: tempDir }
    );
    assert.equal(installed.status, 0, installed.stderr || installed.stdout);

    const cli = path.join(tempDir, "node_modules", "guard-dog", "src", "index.js");
    const guardogHome = path.join(tempDir, "guardog-home");
    const isolatedEnvironment = {
      ...process.env,
      GUARDOG_HOME: guardogHome,
      VIRUSTOTAL_API_KEY: "",
    };

    const setup = run(process.execPath, [cli, "setup", "--quick"], {
      cwd: tempDir,
      env: isolatedEnvironment,
    });
    assert.equal(setup.status, 0, setup.stderr || setup.stdout);
    assert.match(setup.stdout, /OSV scanning is ready now/);
    assert.match(setup.stdout, /No background job or global git hook was installed or changed/);

    const doctor = run(
      process.execPath,
      [cli, "doctor"],
      { cwd: tempDir, env: isolatedEnvironment }
    );
    assert.equal(doctor.status, 0, doctor.stderr || doctor.stdout);
    assert.match(doctor.stdout, /Guardog doctor/);

    const version = run(
      process.execPath,
      [cli, "--version"],
      { cwd: tempDir, env: isolatedEnvironment }
    );
    assert.equal(version.status, 0, version.stderr || version.stdout);
    assert.equal(version.stdout.trim(), "1.2.0");

    const packageManagerMarker = path.join(tempDir, "package-manager-ran");
    const fakeBin = path.join(tempDir, "fake-bin");
    fs.mkdirSync(fakeBin);
    const fakeNpm = path.join(fakeBin, "npm");
    const fakePython = path.join(tempDir, "fake-python");
    const packageManagerStub = `#!/bin/sh\nprintf '%s\\n' "$*" >> "${packageManagerMarker}"\nexit 0\n`;
    fs.writeFileSync(fakeNpm, packageManagerStub, { mode: 0o755 });
    fs.writeFileSync(fakePython, packageManagerStub, { mode: 0o755 });

    const fetchFixture = path.join(tempDir, "fetch-fixture.mjs");
    fs.writeFileSync(
      fetchFixture,
      `globalThis.fetch = async (input) => {
  const url = String(input);
  let body = {};
  if (url.includes('registry.npmjs.org')) {
    body = { name: 'lodash', 'dist-tags': { latest: '4.17.21' }, versions: { '4.17.21': { license: 'MIT' } }, maintainers: [{}] };
  } else if (url.includes('api.npmjs.org/downloads')) {
    body = { downloads: 1000000 };
  } else if (url.includes('pypi.org')) {
    body = { info: { name: 'requests', version: '2.32.3', summary: 'fixture', license: 'Apache-2.0' }, releases: { '2.32.3': [{}] } };
  } else if (url.includes('api.osv.dev')) {
    body = { vulns: [] };
  }
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
};\n`
    );

    const guardedEnvironment = {
      ...isolatedEnvironment,
      GUARDOG_PYTHON: fakePython,
      NODE_OPTIONS: `--import=${fetchFixture}`,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`,
    };

    const guardedNpm = run(
      process.execPath,
      [cli, "install", "npm", "install", "lodash@4.17.21"],
      { cwd: tempDir, env: guardedEnvironment }
    );
    assert.equal(guardedNpm.status, 0, guardedNpm.stderr || guardedNpm.stdout);
    assert.match(fs.readFileSync(packageManagerMarker, "utf8"), /install lodash@4\.17\.21/);

    const guardedPip = run(
      process.execPath,
      [cli, "install", "pip", "install", "requests==2.32.3"],
      { cwd: tempDir, env: guardedEnvironment }
    );
    assert.equal(guardedPip.status, 0, guardedPip.stderr || guardedPip.stdout);
    assert.match(fs.readFileSync(packageManagerMarker, "utf8"), /-m pip install requests==2\.32\.3/);

    fs.rmSync(packageManagerMarker);
    const unsupportedPip = run(
      process.execPath,
      [cli, "install", "pip", "install", "-r", "requirements.txt"],
      {
        cwd: tempDir,
        env: guardedEnvironment,
      }
    );
    assert.equal(unsupportedPip.status, 1, unsupportedPip.stderr || unsupportedPip.stdout);
    assert.match(unsupportedPip.stderr, /cannot safely scan/i);
    assert.equal(fs.existsSync(packageManagerMarker), false, "pip must not run when Guardog cannot scan the request");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("legacy installer delegates to the safe setup path", () => {
  const installer = fs.readFileSync(path.join(repoRoot, "install.sh"), "utf8");
  assert.match(installer, /node "\$guardog_dir\/src\/index\.js" setup --quick/);
  assert.doesNotMatch(installer, /^guardog setup --quick$/m);
  assert.doesNotMatch(installer, /git config --global/);
  assert.doesNotMatch(installer, /Paste your VirusTotal API key/);
});
