#!/usr/bin/env node
/**
 * SSH Tunnel Health Check
 * Checks that the SSH tunnels running as launchd services are alive:
 *   com.myos.dittofeed-tunnel   → localhost:3006  (Dittofeed UI)
 *   com.myos.job-queue-tunnel   → 127.0.0.1:14000 (job queue /health)
 *   com.myos.postiz-tunnel      → localhost:4200  (Postiz social scheduler)
 * Legacy tunnel aliases are still accepted during migration.
 *
 * Sends a Telegram alert if either tunnel is down.
 *
 * Usage:
 *   node bin/tunnel-health-check.js
 *
 * Cron (every 5 minutes):
 *   * /5 * * * * /opt/homebrew/bin/node /path/to/bin/tunnel-health-check.js >> /path/to/data/cron.log 2>&1
 */

import fetch from 'node-fetch';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawnSync } from 'child_process';
import dotenv from 'dotenv';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const LEGACY_NAMESPACE = Buffer.from('b3BlbmNsYXc=', 'base64').toString('utf8');
const legacyTunnelLabel = (suffix) => `com.${LEGACY_NAMESPACE}.${suffix}`;

// Load env: first try the guard-dog local .env, then fall back to workspace .env
dotenv.config({ path: join(rootDir, '.env') });
if (!process.env.TELEGRAM_BOT_TOKEN) {
  dotenv.config({ path: join(rootDir, '../../.env') });
}

// ---- Tunnel definitions -----------------------------------------------

const TUNNELS = [
  {
    name: 'dittofeed-tunnel',
    launchd: 'com.myos.dittofeed-tunnel',
    legacyLaunchd: legacyTunnelLabel('dittofeed-tunnel'),
    url: 'http://127.0.0.1:3006',
    // Dittofeed serves HTML — any 2xx or 3xx response means the tunnel is up
    validate: (status, _body) => status >= 200 && status < 400,
  },
  {
    name: 'job-queue-tunnel',
    launchd: 'com.myos.job-queue-tunnel',
    legacyLaunchd: legacyTunnelLabel('job-queue-tunnel'),
    url: 'http://127.0.0.1:14000/health',
    // Job queue health endpoint returns {"status":"ok"}
    validate: (status, body) => {
      if (status !== 200) return false;
      try {
        const json = JSON.parse(body);
        return json.status === 'ok';
      } catch {
        return false;
      }
    },
  },
  {
    name: 'postiz-tunnel',
    launchd: 'com.myos.postiz-tunnel',
    legacyLaunchd: legacyTunnelLabel('postiz-tunnel'),
    url: 'http://127.0.0.1:4200',
    // Postiz serves HTML — any 2xx or 3xx means tunnel is up
    validate: (status, _body) => status >= 200 && status < 400,
  },
];

const TIMEOUT_MS = 5000;

// ---- Alert suppression state ------------------------------------------
// Tracks whether an alert has already been sent for the current outage.
// Cleared when all tunnels return healthy so the next outage gets a fresh alert.

const ALERT_STATE_FILE = join(rootDir, 'data/tunnel-alert-state.json');

function isAlertSuppressed() {
  if (!existsSync(ALERT_STATE_FILE)) return false;
  try {
    const state = JSON.parse(readFileSync(ALERT_STATE_FILE, 'utf8'));
    return state.alertActive === true;
  } catch {
    return false;
  }
}

function markAlertSent() {
  writeFileSync(ALERT_STATE_FILE, JSON.stringify({ alertActive: true, sentAt: new Date().toISOString() }));
}

function clearAlertState() {
  if (existsSync(ALERT_STATE_FILE)) unlinkSync(ALERT_STATE_FILE);
}

// ---- HTTP probe -------------------------------------------------------

async function probeTunnel(tunnel) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const response = await fetch(tunnel.url, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'manual', // treat 3xx as success for Dittofeed
    });
    clearTimeout(timer);

    const body = await response.text().catch(() => '');
    const ok = tunnel.validate(response.status, body);

    return { ok, status: response.status, error: null };
  } catch (err) {
    return { ok: false, status: null, error: err.message };
  }
}

// ---- Auto-recovery ----------------------------------------------------

const RECOVERY_WAIT_MS = 8000;

function restartTunnel(tunnel) {
  const labels = [tunnel.launchd, tunnel.legacyLaunchd].filter(Boolean);
  for (const label of labels) {
    console.log(`  RECOVERY  Attempting launchctl kickstart for ${label}`);
    // kickstart -k kills the existing job (if any) and starts it fresh
    const result = spawnSync(
      'launchctl',
      ['kickstart', '-k', `gui/${process.getuid()}/${label}`],
      { encoding: 'utf8', timeout: 10000 }
    );
    if (result.error) {
      console.log(`  RECOVERY  launchctl error for ${label}: ${result.error.message}`);
      continue;
    }
    if (result.status === 0) {
      console.log(`  RECOVERY  launchctl kickstart OK for ${label}`);
      return;
    }
    const stderr = (result.stderr || '').trim();
    console.log(`  RECOVERY  launchctl exited ${result.status} for ${label}${stderr ? ': ' + stderr : ''}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---- Telegram alert ---------------------------------------------------

async function sendAlert(downTunnels, restartAttempted = false) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!botToken || !chatId) {
    console.error('Telegram credentials missing — cannot send alert');
    return false;
  }

  const lines = downTunnels.map(({ tunnel, result }) => {
    const detail = result.error
      ? `error: ${result.error}`
      : `HTTP ${result.status}`;
    return `• \`${tunnel.name}\` (${tunnel.url}) — ${detail}`;
  });

  const recoveryNote = restartAttempted
    ? `\n⚠️ _Auto-restart was attempted (launchctl kickstart) but tunnel is still down._\n`
    : ``;

  const message =
    `🚨 *GUARD DOG: SSH TUNNEL DOWN*\n\n` +
    `The following tunnel(s) are not responding:\n\n` +
    lines.join('\n') +
    recoveryNote +
    `\n\nRestart with:\n` +
    downTunnels
      .map(({ tunnel }) => {
        const labels = [tunnel.launchd, tunnel.legacyLaunchd].filter(Boolean).join(' or ');
        return `\`launchctl start ${labels}\``;
      })
      .join('\n') +
    `\n\n⏰ ${new Date().toISOString()}`;

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: message,
          parse_mode: 'Markdown',
          disable_web_page_preview: true,
        }),
      }
    );

    if (!response.ok) {
      const err = await response.text();
      console.error('Telegram API error:', err);
      return false;
    }

    return true;
  } catch (err) {
    console.error('Failed to send Telegram alert:', err.message);
    return false;
  }
}

// ---- Main -------------------------------------------------------------

const timestamp = new Date().toISOString();
console.log(`[${timestamp}] Tunnel health check starting`);

const results = await Promise.all(
  TUNNELS.map(async (tunnel) => {
    const result = await probeTunnel(tunnel);
    const icon = result.ok ? 'OK' : 'DOWN';
    const detail = result.ok
      ? `HTTP ${result.status}`
      : result.error ?? `HTTP ${result.status}`;
    console.log(`  ${icon}  ${tunnel.name}  (${detail})`);
    return { tunnel, result };
  })
);

const downTunnels = results.filter(({ result }) => !result.ok);

if (downTunnels.length === 0) {
  clearAlertState();
  console.log('All tunnels healthy.');
} else {
  console.log(`${downTunnels.length} tunnel(s) down — attempting auto-recovery before alert`);

  // Step 1: kick each failed tunnel
  for (const { tunnel } of downTunnels) {
    restartTunnel(tunnel);
  }

  // Step 2: wait for services to come back up
  console.log(`  RECOVERY  Waiting ${RECOVERY_WAIT_MS / 1000}s before re-probe...`);
  await sleep(RECOVERY_WAIT_MS);

  // Step 3: re-probe only the tunnels that were down
  const recheckResults = await Promise.all(
    downTunnels.map(async ({ tunnel }) => {
      const result = await probeTunnel(tunnel);
      const icon = result.ok ? 'OK' : 'STILL DOWN';
      const detail = result.ok
        ? `HTTP ${result.status}`
        : result.error ?? `HTTP ${result.status}`;
      console.log(`  RECHECK  ${icon}  ${tunnel.name}  (${detail})`);
      return { tunnel, result };
    })
  );

  const stillDown = recheckResults.filter(({ result }) => !result.ok);

  if (stillDown.length === 0) {
    clearAlertState();
    console.log('All tunnels recovered via launchctl kickstart. No alert sent.');
  } else if (isAlertSuppressed()) {
    console.log(`${stillDown.length} tunnel(s) still down — alert already sent for this outage, suppressing.`);
    process.exit(1);
  } else {
    console.log(`${stillDown.length} tunnel(s) still down after restart attempt — sending alert`);
    const sent = await sendAlert(stillDown, /* restartAttempted= */ true);
    if (sent) {
      markAlertSent();
      console.log('Telegram alert sent.');
    } else {
      console.log('Telegram alert FAILED.');
    }
    process.exit(1);
  }
}
