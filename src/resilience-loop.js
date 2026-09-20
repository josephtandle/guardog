import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { guardogDataDir } from './paths.js';

const categoryRules = [
  ['scan_roots', /scan root|no installed dependencies|no verified dependency coverage/i],
  ['schedule', /schedule|crontab|task scheduler|registration/i],
  ['runner', /runner/i],
  ['virustotal', /virustotal|quota/i],
  ['coverage', /coverage|scan status|scan failed|nightly run|receipt/i],
];

const nextActions = {
  scan_roots: 'Choose at least one explicit project folder, then run a nightly scan and verify a non-zero dependency count.',
  schedule: 'Inspect the existing OS schedule. Preserve customized commands, then explicitly enable or repair only the owned registration.',
  runner: 'Run myos-guard-dog doctor --repair, then verify the owned runner is ready.',
  virustotal: 'Run myos-guard-dog test and resolve authentication, freshness, or quota limits without weakening coverage.',
  coverage: 'Inspect the latest nightly receipt and restore exact lockfile or installed-version coverage.',
  operational: 'Run myos-guard-dog doctor --json and resolve the reported operational failure before relying on protection.',
};

function categoryFor(issue) {
  return categoryRules.find(([, pattern]) => pattern.test(issue))?.[0] || 'operational';
}

function readState(statePath) {
  if (!existsSync(statePath)) return { version: 1, cycles: 0, healthyStreak: 0, active: {}, history: {} };
  try {
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    if (state?.version === 1 && Number.isInteger(state.cycles) && state.active && typeof state.active === 'object') return state;
  } catch { /* Invalid generated state is replaced by the next verified cycle. */ }
  return { version: 1, cycles: 0, healthyStreak: 0, active: {}, history: {} };
}

export function recordResilienceCycle({ phase, health, receipt = null, statePath = join(guardogDataDir(), 'resilience-state.json'), now = () => new Date() }) {
  const timestamp = now().toISOString();
  const issues = [...(health?.issues || []), ...(receipt?.issues || [])];
  const operational = health?.ok === true && (!receipt || receipt.status !== 'incomplete');
  const previous = readState(statePath);
  const active = {};
  const history = operational ? {} : { ...(previous.history || previous.active) };
  if (!operational) {
    for (const category of new Set(issues.map(categoryFor))) {
      const prior = history[category];
      active[category] = {
        count: (prior?.count || 0) + 1,
        firstSeenAt: prior?.firstSeenAt || timestamp,
        lastSeenAt: timestamp,
      };
      history[category] = active[category];
    }
  }
  const boundedHistory = Object.fromEntries(Object.entries(history)
    .sort(([, left], [, right]) => right.lastSeenAt.localeCompare(left.lastSeenAt))
    .slice(0, 8));
  const escalations = Object.entries(active)
    .filter(([, value]) => value.count >= 2)
    .map(([category, value]) => ({ category, count: value.count, nextAction: nextActions[category] }));
  const state = {
    version: 1,
    taskClass: 'security_health',
    cycles: previous.cycles + 1,
    lastPhase: phase,
    lastCheckedAt: timestamp,
    lastOperational: operational,
    healthyStreak: operational ? previous.healthyStreak + 1 : 0,
    lastRepairsCount: health?.repairs?.length || 0,
    active,
    history: boundedHistory,
    escalations,
  };
  mkdirSync(dirname(statePath), { recursive: true });
  const temporary = `${statePath}.${process.pid}.tmp`;
  writeFileSync(temporary, JSON.stringify(state, null, 2), { mode: 0o600 });
  renameSync(temporary, statePath);
  return state;
}
