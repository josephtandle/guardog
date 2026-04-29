import { existsSync, mkdirSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import os from 'os';

export function packageRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..');
}

export function guardogHome() {
  return resolve(process.env.GUARDOG_HOME || join(os.homedir(), '.guardog'));
}

export function guardogConfigPath() {
  return join(guardogHome(), 'config.json');
}

export function guardogEnvPath() {
  return join(guardogHome(), '.env');
}

export function guardogDataDir() {
  return join(guardogHome(), 'data');
}

export function ensureGuardogHome() {
  const home = guardogHome();
  for (const dir of [
    home,
    guardogDataDir(),
    join(guardogDataDir(), 'cache'),
    join(guardogDataDir(), 'logs'),
    join(guardogDataDir(), 'reports'),
    join(home, 'bin'),
    join(home, 'hooks')
  ]) {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }
  return home;
}
