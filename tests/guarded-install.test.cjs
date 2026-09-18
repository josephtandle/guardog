const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

test('resolves and approves transitive artifacts before modifying project or installing', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-install-test-'));
  const original = JSON.stringify({ name: 'fixture', version: '1.0.0' });
  fs.writeFileSync(path.join(cwd, 'package.json'), original);
  const bytes = Buffer.from('test artifact');
  const integrity = 'sha512-' + crypto.createHash('sha512').update(bytes).digest('base64');
  const calls = [], scans = [];
  const runner = (command, args, options) => {
    calls.push(args);
    if (args[0] === 'install') {
      assert.equal(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'), original);
      fs.writeFileSync(path.join(options.cwd, 'package-lock.json'), JSON.stringify({lockfileVersion:3,packages:{'':{name:'fixture'},'node_modules/direct':{version:'1.0.0',resolved:'https://registry.npmjs.org/direct/-/direct-1.0.0.tgz',integrity},'node_modules/direct/node_modules/child':{version:'2.0.0',resolved:'https://registry.npmjs.org/child/-/child-2.0.0.tgz',integrity}}}));
    } else {
      assert.equal(scans.length, 2);
      assert.ok(args.includes('--ignore-scripts'));
    }
    return {status:0};
  };
  class Dog { async analyze(...args) { scans.push(args); return {decision:{installAllowed:true}}; } }
  try {
    await runGuardedInstall(['direct'], Dog, {cwd,runner,fetchArtifact:async()=>bytes});
    assert.deepEqual(scans.map(x=>[x[0],x[3]]), [['direct','1.0.0'],['child','2.0.0']]);
    assert.equal(calls.length, 2);
  } finally { fs.rmSync(cwd, {recursive:true,force:true}); }
});

test('unsupported flags, sources and pip never invoke a package manager', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  for (const args of [['pip','requests'], ['npm','--global','foo'], ['foo@https://evil.test/file'], ['foo;echo'], ['foo@npm:bar']]) {
    let called = false;
    await assert.rejects(runGuardedInstall(args, class {}, {runner:()=>{called=true;}}));
    assert.equal(called, false);
  }
});

test('unapproved transitive dependency, corrupt artifact and concurrent edit stop installation', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  for (const scenario of ['denied','integrity','changed','unknown']) {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-install-test-'));
    const original = JSON.stringify({name:'fixture',version:'1.0.0'});
    fs.writeFileSync(path.join(cwd, 'package.json'), original);
    const bytes = Buffer.from('artifact');
    const integrity = 'sha512-' + crypto.createHash('sha512').update(bytes).digest('base64');
    let executions = 0;
    const runner = (command,args,options) => {
      executions++;
      fs.writeFileSync(path.join(options.cwd,'package-lock.json'), JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/child':{version:'2.0.0',resolved:'https://registry.npmjs.org/child/-/child.tgz',integrity}}}));
      return {status:0};
    };
    class Dog { async analyze() {
      if (scenario === 'changed') fs.writeFileSync(path.join(cwd,'package.json'), original + '\n');
      return {decision:scenario === 'unknown' ? {action:'SILENT'} : {installAllowed:scenario !== 'denied'}};
    } }
    try {
      await assert.rejects(runGuardedInstall(['child'], Dog, {cwd,runner,fetchArtifact:async()=>scenario === 'integrity' ? Buffer.from('wrong') : bytes}));
      assert.equal(executions, 1);
      assert.equal(fs.existsSync(path.join(cwd,'package-lock.json')), false);
      assert.equal(fs.readFileSync(path.join(cwd,'package.json'),'utf8'), original + (scenario === 'changed' ? '\n' : ''));
    } finally { fs.rmSync(cwd,{recursive:true,force:true}); }
  }
});
