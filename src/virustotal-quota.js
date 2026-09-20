import { existsSync, openSync, readFileSync, closeSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ensureGuardogHome, guardogDataDir } from './paths.js';

const utcDay = now => new Date(now).toISOString().slice(0, 10);

/** Persist a small, cross-process daily request allowance for the public VT API. */
export class VirusTotalQuota {
  constructor({ limit, now = () => Date.now(), path = join(guardogDataDir(), 'virustotal-quota.json') }) {
    this.limit = limit;
    this.now = now;
    this.path = path;
    this.lockPath = path + '.lock';
  }

  reserve() {
    if (!Number.isInteger(this.limit) || this.limit < 1) return { allowed: true, unlimited: true };
    ensureGuardogHome();
    let descriptor;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { descriptor = openSync(this.lockPath, 'wx', 0o600); break; }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    if (descriptor === undefined) throw new Error('VirusTotal quota ledger is busy; no request was sent.');
    try {
      const day = utcDay(this.now());
      let state = { day, used: 0 };
      if (existsSync(this.path)) {
        try {
          const parsed = JSON.parse(readFileSync(this.path, 'utf8'));
          if (parsed?.day === day && Number.isInteger(parsed.used) && parsed.used >= 0) state = parsed;
        } catch { /* Start a new UTC-day record when the existing ledger is malformed. */ }
      }
      if (state.used >= this.limit) return { allowed: false, used: state.used, limit: this.limit, day };
      state.used++;
      writeFileSync(this.path, JSON.stringify({ day, used: state.used, limit: this.limit, updatedAt: new Date(this.now()).toISOString() }) + '\n', { mode: 0o600 });
      return { allowed: true, used: state.used, limit: this.limit, day };
    } finally {
      closeSync(descriptor);
      unlinkSync(this.lockPath);
    }
  }
}
