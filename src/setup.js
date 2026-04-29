import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import os from 'os';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

import {
  ensureGuardogHome,
  guardogConfigPath,
  guardogEnvPath,
  guardogHome,
  packageRoot
} from './paths.js';

const DEFAULT_CONFIG = {
  nightlyUpdates: false,
  nightlyTime: '00:00',
  guardedInstalls: true,
  gitPreCommitHook: false,
  virustotalConfigured: false
};

const CRON_MARKER = '# guardog-nightly';

function readJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return fallback;
  }
}

export function loadUserConfig() {
  return {
    ...DEFAULT_CONFIG,
    ...readJson(guardogConfigPath(), {})
  };
}

export function saveUserConfig(config) {
  ensureGuardogHome();
  writeFileSync(guardogConfigPath(), JSON.stringify({ ...DEFAULT_CONFIG, ...config }, null, 2));
}

function yes(answer) {
  return /^(y|yes)$/i.test(answer.trim());
}

export function installGitHook() {
  const root = packageRoot();
  const hookSource = join(root, 'bin', 'git-precommit-hook.sh');
  if (process.platform === 'win32') {
    return {
      ok: false,
      message: 'Global git pre-commit hook install is skipped on Windows. Use guardog install before dependency installs.'
    };
  }
  if (!existsSync(hookSource)) {
    return { ok: false, message: `Missing hook source: ${hookSource}` };
  }
  const hooksDir = join(guardogHome(), 'hooks');
  const hookDest = join(hooksDir, 'pre-commit');
  const existing = spawnSync('git', ['config', '--global', '--get', 'core.hooksPath'], { encoding: 'utf-8' });
  const existingPath = existing.status === 0 ? existing.stdout.trim() : '';
  if (existingPath && existingPath !== hooksDir) {
    return {
      ok: false,
      message: `Existing global git hooksPath is set to ${existingPath}. Guardog did not overwrite it.`
    };
  }
  writeFileSync(hookDest, readFileSync(hookSource, 'utf-8'));
  spawnSync('chmod', ['+x', hookDest], { stdio: 'ignore' });
  const result = spawnSync('git', ['config', '--global', 'core.hooksPath', hooksDir], { encoding: 'utf-8' });
  if (result.status !== 0) {
    return { ok: false, message: result.stderr || 'git config failed' };
  }
  return { ok: true, message: `Git pre-commit hook installed at ${hookDest}` };
}

export function removeGitHook() {
  if (process.platform === 'win32') {
    return { ok: true, message: 'No Windows global git hook was installed by Guardog.' };
  }
  const hooksDir = join(guardogHome(), 'hooks');
  const existing = spawnSync('git', ['config', '--global', '--get', 'core.hooksPath'], { encoding: 'utf-8' });
  const existingPath = existing.status === 0 ? existing.stdout.trim() : '';
  if (existingPath !== hooksDir) {
    return { ok: true, message: 'Guardog is not the active global git hooksPath.' };
  }
  const result = spawnSync('git', ['config', '--global', '--unset', 'core.hooksPath'], { encoding: 'utf-8' });
  return {
    ok: result.status === 0,
    message: result.status === 0 ? 'Guardog global git hook disabled.' : result.stderr || 'git config unset failed'
  };
}

export function installNightlySchedule() {
  ensureGuardogHome();
  if (process.platform === 'win32') {
    const taskCommand = `${process.execPath} "${join(packageRoot(), 'bin', 'nightly-scan.js')}"`;
    const result = spawnSync('schtasks', [
      '/Create',
      '/TN',
      'GuardogNightlyScan',
      '/SC',
      'DAILY',
      '/ST',
      '00:00',
      '/TR',
      taskCommand,
      '/F'
    ], { encoding: 'utf-8', shell: true });
    return {
      ok: result.status === 0,
      message: result.status === 0 ? 'Windows scheduled task GuardogNightlyScan installed for midnight.' : result.stderr || result.stdout
    };
  }

  const cronCommand = `${process.execPath} "${join(packageRoot(), 'src', 'index.js')}" nightly`;
  const cronLine = `0 0 * * * ${cronCommand} >> "${join(guardogHome(), 'data', 'logs', 'nightly.log')}" 2>&1 ${CRON_MARKER}`;
  const existing = spawnSync('crontab', ['-l'], { encoding: 'utf-8' });
  const current = existing.status === 0 ? existing.stdout : '';
  const next = current
    .split('\n')
    .filter(line => line.trim() && !line.includes(CRON_MARKER))
    .concat(cronLine)
    .join('\n') + '\n';
  const result = spawnSync('crontab', ['-'], { input: next, encoding: 'utf-8' });
  return {
    ok: result.status === 0,
    message: result.status === 0 ? 'Cron schedule installed for midnight.' : result.stderr || 'crontab update failed'
  };
}

export function removeNightlySchedule() {
  if (process.platform === 'win32') {
    const result = spawnSync('schtasks', ['/Delete', '/TN', 'GuardogNightlyScan', '/F'], { encoding: 'utf-8', shell: true });
    return {
      ok: result.status === 0,
      message: result.status === 0 ? 'Windows scheduled task removed.' : result.stderr || result.stdout
    };
  }

  const existing = spawnSync('crontab', ['-l'], { encoding: 'utf-8' });
  if (existing.status !== 0) {
    return { ok: true, message: 'No crontab found.' };
  }
  const next = existing.stdout
    .split('\n')
    .filter(line => !line.includes(CRON_MARKER))
    .join('\n') + '\n';
  const result = spawnSync('crontab', ['-'], { input: next, encoding: 'utf-8' });
  return {
    ok: result.status === 0,
    message: result.status === 0 ? 'Cron schedule removed.' : result.stderr || 'crontab update failed'
  };
}

export async function runSetup() {
  ensureGuardogHome();
  const rl = readline.createInterface({ input, output });
  const config = loadUserConfig();

  console.log('\nGuardog setup');
  console.log(`State folder: ${guardogHome()}`);
  console.log('Guardog uses local checks plus public package/security APIs. No OpenAI or LLM token usage is required.');
  console.log('Nightly feed updates and install protections are opt-in/explicit so nothing silently changes your machine.\n');

  const nightly = await rl.question('Run Guardog every night at midnight? [y/N] ');
  config.nightlyUpdates = yes(nightly);
  if (config.nightlyUpdates) {
    const result = installNightlySchedule();
    console.log(result.ok ? `OK: ${result.message}` : `Skipped: ${result.message}`);
  } else {
    const result = removeNightlySchedule();
    console.log(result.ok ? `OK: ${result.message}` : `Skipped: ${result.message}`);
  }

  const guarded = await rl.question('Use Guardog before dependency installs? [Y/n] ');
  config.guardedInstalls = guarded.trim() === '' || yes(guarded);
  if (config.guardedInstalls) {
    console.log('Use `guardog install <npm-package>` instead of `npm install <npm-package>` for a pre-install scan.');
  }

  const hook = await rl.question('Install global git pre-commit dependency scan hook? [y/N] ');
  config.gitPreCommitHook = yes(hook);
  if (config.gitPreCommitHook) {
    const result = installGitHook();
    console.log(result.ok ? `OK: ${result.message}` : `Skipped: ${result.message}`);
  } else {
    const result = removeGitHook();
    console.log(result.ok ? `OK: ${result.message}` : `Skipped: ${result.message}`);
  }

  const vtKey = await rl.question('VirusTotal API key (press Enter to skip): ');
  if (vtKey.trim()) {
    writeFileSync(guardogEnvPath(), `VIRUSTOTAL_API_KEY=${vtKey.trim()}${os.EOL}`);
    config.virustotalConfigured = true;
    console.log(`Saved VirusTotal key to ${guardogEnvPath()}`);
  } else if (!existsSync(guardogEnvPath())) {
    writeFileSync(guardogEnvPath(), '');
  }

  saveUserConfig(config);
  rl.close();

  console.log('\nGuardog setup complete.');
  console.log('This feature is turned off by default, but you can turn on nightly updates with `guardog updates enable`.');
}

export function printDoctor() {
  ensureGuardogHome();
  const checks = [
    ['Node', process.version],
    ['Platform', `${process.platform} ${process.arch}`],
    ['State folder', guardogHome()],
    ['Config', existsSync(guardogConfigPath()) ? guardogConfigPath() : 'missing'],
    ['VirusTotal', existsSync(guardogEnvPath()) && readFileSync(guardogEnvPath(), 'utf-8').includes('VIRUSTOTAL_API_KEY=') ? 'configured' : 'optional/not configured']
  ];
  console.log('\nGuardog doctor');
  for (const [label, value] of checks) {
    console.log(`${label}: ${value}`);
  }
  console.log('\nInstall checks: use `guardog install <package>` for guarded npm installs.');
}
