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
    await runGuardedInstall(['direct'], Dog, {platform:'linux',cwd,runner,fetchArtifact:async()=>bytes,fetchMetadata:async(name,version)=>({name,version,dist:{tarball:`https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,integrity}})});
    assert.deepEqual(scans.map(x=>[x[0],x[3]]), [['direct','1.0.0'],['child','2.0.0']]);
    assert.equal(calls.length, 2);
  } finally { fs.rmSync(cwd, {recursive:true,force:true}); }
});

test('unsupported flags, sources and pip never invoke a package manager', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  for (const args of [['pip','requests'], ['npm','--global','foo'], ['foo@https://evil.test/file'], ['foo;echo'], ['foo@npm:bar']]) {
    let called = false;
    await assert.rejects(runGuardedInstall(args, class {}, {platform:'linux',runner:()=>{called=true;}}));
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
      await assert.rejects(runGuardedInstall(['child'], Dog, {platform:'linux',cwd,runner,fetchArtifact:async()=>scenario === 'integrity' ? Buffer.from('wrong') : bytes,fetchMetadata:async(name,version)=>({name,version,dist:{tarball:'https://registry.npmjs.org/child/-/child.tgz',integrity}})}));
      assert.equal(executions, 1);
      assert.equal(fs.existsSync(path.join(cwd,'package-lock.json')), false);
      assert.equal(fs.readFileSync(path.join(cwd,'package.json'),'utf8'), original + (scenario === 'changed' ? '\n' : ''));
    } finally { fs.rmSync(cwd,{recursive:true,force:true}); }
  }
});

test('rejects lockfile version impersonation before artifact scanning or install', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  for (const mismatch of ['url','integrity','name','version']) {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(),'guardog-identity-test-'));
    const original = JSON.stringify({name:'fixture',version:'1.0.0'});
    fs.writeFileSync(path.join(cwd,'package.json'), original);
    const bytes = Buffer.from('old vulnerable release');
    const integrity = 'sha512-' + crypto.createHash('sha512').update(bytes).digest('base64');
    let commands = 0, scanned = 0, downloaded = 0;
    const runner = (command,args,options) => {
      commands++;
      fs.writeFileSync(path.join(options.cwd,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/child':{version:'2.0.0',resolved:'https://registry.npmjs.org/child/-/child-1.0.0.tgz',integrity}}}));
      return {status:0};
    };
    class Dog { async analyze() {scanned++; return {decision:{installAllowed:true}};} }
    const fetchMetadata = async (name,version) => {
      assert.equal(name,'child'); assert.equal(version,'2.0.0');
      return {name:mismatch==='name'?'other':name,version:mismatch==='version'?'1.0.0':version,dist:{tarball:`https://registry.npmjs.org/child/-/child-${mismatch==='url'?'2':'1'}.0.0.tgz`,integrity:mismatch==='integrity'?'sha512-different':integrity}};
    };
    try {
      await assert.rejects(runGuardedInstall(['child'],Dog,{platform:'linux',cwd,runner,fetchMetadata,fetchArtifact:async()=>{downloaded++; return bytes;}}),/Registry artifact identity mismatch/);
      assert.equal(commands,1); assert.equal(scanned,0); assert.equal(downloaded,0);
      assert.equal(fs.readFileSync(path.join(cwd,'package.json'),'utf8'),original);
      assert.equal(fs.existsSync(path.join(cwd,'package-lock.json')),false);
    } finally {fs.rmSync(cwd,{recursive:true,force:true});}
  }
});

test('Windows discovers npm-cli.js and passes arguments directly to Node without a shell', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-windows-test-'));
  // Spaces and shell metacharacters must remain literal path arguments.
  const npmRoot = path.join(root, 'Node & Tools');
  const cli = path.join(npmRoot, 'node_modules', 'npm', 'bin', 'npm-cli.js');
  const cwd = path.join(root, 'Project & Files');
  fs.mkdirSync(path.dirname(cli), {recursive:true});
  fs.writeFileSync(cli, '// Fixture only, never executed');
  fs.mkdirSync(cwd);
  fs.writeFileSync(path.join(cwd,'package.json'), JSON.stringify({name:'fixture',version:'1.0.0'}));
  const bytes = Buffer.from('fixture artifact');
  const integrity = 'sha512-' + crypto.createHash('sha512').update(bytes).digest('base64');
  const resolved = 'https://registry.npmjs.org/child/-/child-2.0.0.tgz';
  const commands = [];
  let scanned = false;
  const runner = (command,args,options) => {
    commands.push({command,args});
    assert.equal(options.shell,false);
    if (command === 'where.exe') {
      assert.deepEqual(args,['npm.cmd']);
      return {status:0,stdout:path.join(npmRoot,'npm.cmd')+'\r\n'};
    }
    assert.equal(command,process.execPath);
    assert.equal(args[0],cli);
    assert.ok(args.includes('--ignore-scripts'));
    if (args[1] === 'install') {
      assert.equal(args[2],'child@2.0.0');
      assert.ok(args.includes('--package-lock-only'));
      assert.equal(scanned,false);
      fs.writeFileSync(path.join(options.cwd,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/child':{version:'2.0.0',resolved,integrity}}}));
    } else {
      assert.equal(args[1],'ci');
      assert.equal(options.cwd,cwd);
      assert.equal(scanned,true);
    }
    return {status:0};
  };
  class Dog { async analyze(name,ecosystem,hash,version) {
    assert.equal(name,'child'); assert.equal(version,'2.0.0');
    scanned = true;
    return {decision:{installAllowed:true}};
  } }
  try {
    await runGuardedInstall(['npm','child@2.0.0'],Dog,{platform:'win32',cwd,runner,fetchArtifact:async()=>bytes,fetchMetadata:async(name,version)=>({name,version,dist:{tarball:resolved,integrity}})});
    assert.equal(commands.length,3);
    assert.equal(commands[0].command,'where.exe');
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
