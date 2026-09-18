import { chmodSync, existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ensureGuardogHome, guardogConfigPath, guardogEnvPath, guardogHome } from './paths.js';
import { inspectSchedule, registerSchedule, inspectRunner, repairRunner, scheduleSpec } from './scheduler.js';

/** Repair only local state and an already opted-in missing Guardog schedule. */
export function checkHealth(options = {}) {
  const issues = [];
  const repairs = [];
  const configPath = guardogConfigPath();
  let config = {};
  try {
    config = JSON.parse(readFileSync(configPath, 'utf8'));
    if (!config || Array.isArray(config) || typeof config !== 'object') throw new Error('Expected a config object.');
  } catch (error) {
    config = {};
    issues.push(existsSync(configPath) ? 'Config is invalid; restore it or run setup after reviewing the file.' : 'Setup has not been completed. Run guardog setup --quick.');
  }
  if (options.repair) {
    try {
      ensureGuardogHome();
      repairs.push('Ensured local state directories exist.');
      if (process.platform !== 'win32' && existsSync(guardogEnvPath())) {
        chmodSync(guardogEnvPath(), 0o600);
        repairs.push('Restricted local credential-file permissions.');
      }
    } catch (error) { issues.push('Local state repair failed: ' + error.message); }
  }
  let schedule;
  try { schedule = inspectSchedule(config, options); }
  catch (error) { schedule = { state: 'unknown', registered: false, detail: error.message }; }
  if (options.repair && config.nightlyUpdates === true && schedule.state === 'missing') {
    if (!Array.isArray(config.scanRoots) || !config.scanRoots.length || config.scanRoots.some(root => typeof root !== 'string' || !existsSync(root))) {
      issues.push('Cannot restore schedule until saved scan roots are available.');
    } else {
      try {
        const result = registerSchedule(config, options);
        if (result.ok) repairs.push('Restored the previously enabled Guardog schedule.');
        else issues.push(result.message);
        schedule = inspectSchedule(config, options);
      } catch (error) { issues.push('Schedule repair failed: ' + error.message); }
    }
  }
  if (config.nightlyUpdates === true && !schedule.registered) issues.push('Nightly scans were enabled but registration is ' + schedule.state + ': ' + schedule.detail);
  let runner = { state: 'unknown', ok: false };
  try {
    const spec = scheduleSpec(config, options);
    runner = inspectRunner(spec);
    if (options.repair && config.nightlyUpdates === true && schedule.registered && !runner.ok) {
      const result = repairRunner(spec);
      if (result.ok && result.changed) repairs.push('Restored the owned nightly runner.');
      else if (!result.ok) issues.push(result.message);
      runner = inspectRunner(spec);
    }
  } catch (error) { issues.push('Cannot inspect or repair nightly runner: ' + error.message); }
  if (config.nightlyUpdates === true && !runner.ok) issues.push('Nightly runner is ' + runner.state + '.');
  if (config.nightlyUpdates !== true && schedule.registered) issues.push('An actual schedule exists despite disabled config; inspect it before making changes.');
  const roots = Array.isArray(config.scanRoots) ? config.scanRoots : [];
  if (!roots.length) issues.push('No nightly scan roots selected.');
  for (const root of roots) {
    try { if (!statSync(root).isDirectory()) issues.push('Scan root is not a directory: ' + root); }
    catch { issues.push('Scan root unavailable: ' + root); }
  }
  let lastRun = null;
  try { lastRun = JSON.parse(readFileSync(join(guardogHome(), 'data', 'last-nightly.json'), 'utf8')); }
  catch { /* No receipt is reported explicitly below. */ }
  if (config.nightlyUpdates === true) {
    if (!lastRun) issues.push('No completed nightly-run receipt yet. Run guardog nightly now.');
    else {
      const timestamp = Date.parse(lastRun.finishedAt);
      if (!Number.isFinite(timestamp) || Date.now() - timestamp > 36 * 3600000) issues.push('Latest nightly run is missing or older than 36 hours.');
      if (lastRun.status !== 'complete') issues.push('Latest nightly scan status: ' + lastRun.status);
    }
  }
  let configured = Boolean(process.env.VIRUSTOTAL_API_KEY);
  try { configured ||= existsSync(guardogEnvPath()) && /^VIRUSTOTAL_API_KEY=.+$/m.test(readFileSync(guardogEnvPath(), 'utf8')); }
  catch { issues.push('Local VirusTotal configuration cannot be read.'); }
  return { taskClass: 'security_health', ok: issues.length === 0, stateFolder: guardogHome(), scanRoots: roots, nightlyEnabled: config.nightlyUpdates === true, schedule, runner, lastRun, virusTotal: configured ? 'configured (authentication not tested)' : 'optional/not configured', osv: 'available without a key (connectivity not tested)', repairs, issues };
}
