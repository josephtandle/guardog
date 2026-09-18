import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync, lstatSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/;
const SELECTOR = /^(?:[a-zA-Z][a-zA-Z0-9._-]*|[~^]?\d+(?:\.\d+){0,2}(?:-[\w.-]+)?(?:\+[\w.-]+)?)$/;

function validateSpec(spec) {
  const split = spec.startsWith('@') ? spec.indexOf('@', 1) : spec.indexOf('@');
  const name = split < 0 ? spec : spec.slice(0, split);
  const selector = split < 0 ? null : spec.slice(split + 1);
  if (!NAME.test(name) || (selector !== null && !SELECTOR.test(selector))) {
    throw new Error(`Unsupported package specification: ${spec}. Use a registry package name, exact version, tag, ^version or ~version.`);
  }
}

function readProjectFile(path) {
  if (!existsSync(path)) return null;
  if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error(`Expected an ordinary project file: ${path}`);
  return readFileSync(path, 'utf8');
}

function npmCommand(platform, runner) {
  if (platform !== 'win32') return { command: 'npm', prefix: [] };
  // Execute npm's JavaScript entry point directly. Never interpolate package names
  // or filesystem paths into cmd.exe, where shell metacharacters can execute.
  const located = runner('where.exe', ['npm.cmd'], { encoding: 'utf8', shell: false });
  for (const entry of (located.stdout || '').trim().split(/\r?\n/)) {
    const cli = join(dirname(entry), 'node_modules', 'npm', 'bin', 'npm-cli.js');
    if (existsSync(cli)) return { command: process.execPath, prefix: [cli] };
  }
  throw new Error('Could not locate npm-cli.js. Repair the Node.js/npm installation, then retry.');
}

async function downloadArtifact(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(30000), redirect: 'error' });
  if (!response.ok) throw new Error(`Artifact download failed (${response.status})`);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 50 * 1024 * 1024) throw new Error('Artifact exceeds the 50 MB verification limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function fetchRegistryMetadata(name, version) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
  const response = await fetch(url, { signal: AbortSignal.timeout(30000), redirect: 'error' });
  if (!response.ok) throw new Error(`Exact registry metadata unavailable for ${name}@${version} (${response.status})`);
  return response.json();
}

/** Resolve and approve the entire npm tree before changing the target project.
 * Lifecycle scripts remain disabled, including after approval. Pip and non-registry
 * dependencies fail closed because this resolver cannot pin their complete tree.
 */
export async function runGuardedInstall(args, GuardDogClass, options = {}) {
  const cwd = options.cwd || process.cwd();
  const runner = options.runner || spawnSync;
  const fetchArtifact = options.fetchArtifact || downloadArtifact;
  const fetchMetadata = options.fetchMetadata || fetchRegistryMetadata;
  const supplied = [...args];
  if (supplied[0] === 'pip' || supplied[0] === 'pip3') {
    throw new Error('Guarded pip installation is not supported: a complete, hash-pinned wheel dependency tree is required. No pip command was run. Use a reviewed hashed requirements lock and audit its exact versions before installing.');
  }
  if (supplied[0] === 'npm') supplied.shift();
  if (['install', 'i', 'add'].includes(supplied[0])) supplied.shift();
  supplied.forEach(validateSpec);
  const paths = ['package.json', 'package-lock.json', 'npm-shrinkwrap.json'].map(name => join(cwd, name));
  const before = paths.map(readProjectFile);
  if (before[2] !== null) throw new Error('Guarded install does not support npm-shrinkwrap.json yet. No changes made.');
  const manifest = before[0] === null ? { name: 'guardog-project', version: '1.0.0', private: true } : JSON.parse(before[0]);
  if (manifest.workspaces || manifest.overrides || manifest.bundledDependencies || manifest.bundleDependencies) {
    throw new Error('Workspaces, overrides and bundled dependencies require a separate reviewed install. No changes made.');
  }
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, version] of Object.entries(manifest[field] || {})) validateSpec(`${name}@${version}`);
  }
  const npm = npmCommand(options.platform || process.platform, runner);
  const staging = mkdtempSync(join(tmpdir(), 'guardog-resolve-'));
  const execute = (argv, directory) => {
    const result = runner(npm.command, [...npm.prefix, ...argv], { cwd: directory, shell: false, stdio: 'inherit' });
    if (result.error || result.status !== 0) throw new Error(`npm ${argv[0]} failed: ${result.error?.message || `exit ${result.status}`}`);
  };
  try {
    writeFileSync(join(staging, 'package.json'), JSON.stringify(manifest, null, 2));
    // Preserve existing locked choices, but reject external/local sources before
    // handing the copied lock to npm's resolver.
    if (before[1] !== null) {
      const previousLock = JSON.parse(before[1]);
      if (![2, 3].includes(previousLock.lockfileVersion) || !previousLock.packages) throw new Error('Upgrade the project lockfile to npm lockfileVersion 2 or 3 before guarded installation.');
      for (const [location, pkg] of Object.entries(previousLock.packages)) {
        if (location === '') continue;
        if (pkg.link || pkg.inBundle || !pkg.resolved) throw new Error(`Unsupported existing locked dependency: ${location}`);
        const url = new URL(pkg.resolved);
        if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password) throw new Error(`Unapproved existing artifact origin: ${location}`);
      }
      writeFileSync(join(staging, 'package-lock.json'), before[1]);
    }
    execute(['install', ...supplied, '--package-lock-only', '--ignore-scripts', '--save-exact', '--registry=https://registry.npmjs.org', '--no-audit', '--no-fund'], staging);
    const approvedManifest = readFileSync(join(staging, 'package.json'), 'utf8');
    const approvedLock = readFileSync(join(staging, 'package-lock.json'), 'utf8');
    const lock = JSON.parse(approvedLock);
    if (![2, 3].includes(lock.lockfileVersion) || !lock.packages) throw new Error('npm did not produce a supported complete lockfile');
    const dog = new GuardDogClass();
    const seen = new Set();
    for (const [location, pkg] of Object.entries(lock.packages)) {
      if (location === '') continue;
      const name = pkg.name || location.split('node_modules/').pop();
      if (!NAME.test(name) || !VERSION.test(pkg.version || '') || pkg.link || pkg.inBundle) throw new Error(`Unverifiable locked dependency: ${location}`);
      const url = new URL(pkg.resolved);
      if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password) throw new Error(`Unapproved artifact origin for ${name}`);
      const integrity = /^(sha512|sha256)-([A-Za-z0-9+/]+={0,2})$/.exec(pkg.integrity || '');
      if (!integrity) throw new Error(`Missing strong artifact integrity for ${name}`);
      const identity = `${name}@${pkg.version}:${pkg.integrity}`;
      // The lock is input, not authority: a valid digest can describe a different
      // release. Bind its exact coordinates AND bytes to public registry metadata.
      const metadata = await fetchMetadata(name, pkg.version);
      if (metadata?.name !== name || metadata?.version !== pkg.version ||
          metadata?.dist?.tarball !== pkg.resolved || metadata?.dist?.integrity !== pkg.integrity) {
        throw new Error(`Registry artifact identity mismatch for ${name}@${pkg.version}`);
      }
      if (seen.has(identity)) continue;
      const bytes = await fetchArtifact(url.href);
      if (createHash(integrity[1]).update(bytes).digest('base64') !== integrity[2]) throw new Error(`Artifact integrity mismatch for ${name}`);
      const hash = createHash('sha256').update(bytes).digest('hex');
      const result = await dog.analyze(name, 'npm', hash, pkg.version);
      if (result?.decision?.installAllowed !== true) throw new Error(`Install blocked: ${name}@${pkg.version} was not explicitly approved. Resolve reported findings or incomplete checks and retry.`);
      seen.add(identity);
    }
    for (let index = 0; index < paths.length; index++) {
      if (readProjectFile(paths[index]) !== before[index]) throw new Error('Project files changed during security checks. No install performed; retry with a stable project.');
    }
    writeFileSync(paths[0], approvedManifest);
    writeFileSync(paths[1], approvedLock);
    execute(['ci', '--ignore-scripts', '--registry=https://registry.npmjs.org', '--no-audit', '--no-fund'], cwd);
    console.log('Guardog installed the approved locked dependency tree. Lifecycle scripts were not executed; packages requiring build scripts need a separate review.');
    return { installed: true, packagesChecked: seen.size, scriptsExecuted: false };
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
