'use strict';

// Self-healing in-process cron.
//
// The pattern this replaces — `setInterval(..., 60*60*1000)` that checks
// `if (new Date().getUTCHours() !== H) return` — silently skips a run when
// the process restarts during the trigger window. Persistent last-run state
// + per-tick "is the most recent scheduled time still unrun?" fixes that.
//
// Usage:
//   const { createCronRunner, dailyAtUtc, weeklyAtUtc } = require('publicwerx-core');
//
//   const cron = createCronRunner({
//     getLastRun: (key) => Number(db.prepare('SELECT value FROM meta WHERE key=?').get(key)?.value) || 0,
//     setLastRun: (key, ms) => db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run(key, String(ms)),
//     intervalMs: 5 * 60 * 1000,
//     onError: (key, err) => console.error('[cron]', key, err.stack || err.message),
//   });
//
//   cron.register('purge.app_logs', dailyAtUtc(4), () => db.purgeLogs.run());
//   cron.register('archive.audit_log', weeklyAtUtc(6, 2), audit.archiveAndPurge);
//   cron.start();
//
// Task keys are namespaced 'cron.<key>' when stored, so they can coexist with
// other meta keys.

function createCronRunner(opts = {}) {
  if (typeof opts.getLastRun !== 'function') {
    throw new Error('publicwerx-core/cron: opts.getLastRun required');
  }
  if (typeof opts.setLastRun !== 'function') {
    throw new Error('publicwerx-core/cron: opts.setLastRun required');
  }

  const getLastRun = opts.getLastRun;
  const setLastRun = opts.setLastRun;
  const intervalMs = opts.intervalMs || 5 * 60 * 1000;
  const initialDelayMs = opts.initialDelayMs ?? 5_000;
  const onError = typeof opts.onError === 'function' ? opts.onError : null;

  const tasks = new Map();
  let timer = null;

  async function runTask(key, task) {
    const storeKey = 'cron.' + key;
    let lastRunMs;
    try {
      lastRunMs = Number(await getLastRun(storeKey)) || 0;
    } catch (err) {
      report(key, err);
      return;
    }
    if (!task.isDue(lastRunMs, Date.now())) return;
    try {
      await task.run();
      await setLastRun(storeKey, Date.now());
    } catch (err) {
      report(key, err);
      // Do NOT update lastRun on failure — let the next tick retry.
    }
  }

  function report(key, err) {
    if (onError) {
      try { onError(key, err); } catch {}
    } else {
      console.error('[cron]', key, err?.stack || err?.message || err);
    }
  }

  async function tick() {
    // Sequential — tasks may share resources (DB, S3). One stuck task delays
    // the others by at most one interval; acceptable for our scale.
    for (const [key, task] of tasks) {
      await runTask(key, task);
    }
  }

  return {
    register(key, isDue, run) {
      if (typeof key !== 'string' || !key) throw new Error('cron.register: key required');
      if (typeof isDue !== 'function') throw new Error('cron.register: isDue required');
      if (typeof run !== 'function') throw new Error('cron.register: run required');
      if (tasks.has(key)) throw new Error(`cron.register: duplicate key ${key}`);
      tasks.set(key, { isDue, run });
    },
    start() {
      if (timer) return;
      // First tick fires soon so a restart that lands in a trigger window
      // doesn't wait the full interval to catch up.
      setTimeout(() => tick().catch(() => {}), initialDelayMs);
      timer = setInterval(() => tick().catch(() => {}), intervalMs);
    },
    stop() {
      if (timer) { clearInterval(timer); timer = null; }
    },
    // Exposed for tests / manual triggers.
    tick,
  };
}

// "isDue" for a daily task scheduled at <hour>:00 UTC.
// Returns true if the most recent occurrence of that hour has passed and
// the task has not run since.
function dailyAtUtc(hour) {
  return (lastRunMs, nowMs) => {
    const now = new Date(nowMs);
    const todaysSchedule = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
      hour,
    );
    const mostRecent = nowMs >= todaysSchedule ? todaysSchedule : todaysSchedule - 86_400_000;
    return lastRunMs < mostRecent;
  };
}

// "isDue" for a weekly task scheduled at day-of-week (0=Sun..6=Sat) + hour UTC.
function weeklyAtUtc(day, hour) {
  return (lastRunMs, nowMs) => {
    const now = new Date(nowMs);
    const scheduled = new Date(Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
      hour,
    ));
    const offsetDays = (now.getUTCDay() - day + 7) % 7;
    scheduled.setUTCDate(scheduled.getUTCDate() - offsetDays);
    if (scheduled.getTime() > nowMs) scheduled.setUTCDate(scheduled.getUTCDate() - 7);
    return lastRunMs < scheduled.getTime();
  };
}

module.exports = { createCronRunner, dailyAtUtc, weeklyAtUtc };
