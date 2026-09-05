/* ==========================================================================
   FIXTURE SYNC SCHEDULER
   Keeps data/fixtures.json fresh without ever touching Football-Data.org
   on a visitor's page load.

   Refresh policy:
     - Normal days .......... every 12 hours
     - Match day ............ every 3 minutes
     - Match finished ....... back to 12 hours

   The scheduler is started once from server.js. The interval is re-evaluated
   on every tick based on whether the next scheduled match is today.
   ========================================================================== */
const {
  syncFixtures,
  updateNextSync,
  getCachedFixtures,
  clearFixturesCache,
} = require('../services/fixture.service');

const NORMAL_INTERVAL_MS = 12 * 60 * 60 * 1000; // 12 hours
const MATCHDAY_INTERVAL_MS = 3 * 60 * 1000;     // 3 minutes

let timer = null;
let syncing = false;
let lastScheduledIntervalMs = NORMAL_INTERVAL_MS;
let lastOnDemandAttempt = 0;

// How long after kickoff a match is still treated as "being played" — 90
// minutes plus half time, stoppage, and a margin for the API catching up.
const IN_PROGRESS_WINDOW_MS = 3.5 * 60 * 60 * 1000;
// How far ahead of kickoff we start polling fast, so the first score of the
// night isn't waiting on a 12-hour timer.
const WARMUP_BEFORE_KICKOFF_MS = 2 * 60 * 60 * 1000;

/**
 * Decide the correct refresh interval for right now.
 *
 * Poll fast whenever a match is actually being played (or is about to be) —
 * that's the only time scores change. Note this deliberately looks at
 * matches that have ALREADY kicked off, not just upcoming ones: a match in
 * progress is exactly when we most need fresh data, and judging the interval
 * purely from the next *unplayed* fixture meant that the moment a match
 * kicked off, the interval was decided by the following fixture — often the
 * next day — and dropped to 12 hours mid-match, freezing the score.
 */
function desiredIntervalMs(cache) {
  const now = Date.now();
  const matches = cache.matches || [];
  let fast = false;

  for (const m of matches) {
    if (['POSTPONED', 'CANCELLED'].includes(m.status)) continue;
    const kickoff = new Date(m.utcDate).getTime();
    if (!Number.isFinite(kickoff)) continue;

    const sinceKickoff = now - kickoff;
    const beingPlayed =
      sinceKickoff >= 0 && sinceKickoff <= IN_PROGRESS_WINDOW_MS && m.status !== 'FINISHED';
    const aboutToStart = sinceKickoff < 0 && -sinceKickoff <= WARMUP_BEFORE_KICKOFF_MS;

    if (beingPlayed || aboutToStart) {
      fast = true;
      break;
    }
  }

  return fast ? MATCHDAY_INTERVAL_MS : NORMAL_INTERVAL_MS;
}

async function runSync(reason) {
  if (syncing) return; // don't overlap syncs
  syncing = true;
  try {
    console.log(`[fixtures] sync (${reason})…`);
    const cache = await syncFixtures();
    const interval = desiredIntervalMs(cache);
    const nextSyncAt = new Date(Date.now() + interval).toISOString();
    updateNextSync(nextSyncAt);

    if (interval !== lastScheduledIntervalMs) {
      console.log(`[fixtures] refresh interval changed to ${interval === MATCHDAY_INTERVAL_MS ? '3 min (match day)' : '12 hours (normal)'}`);
      lastScheduledIntervalMs = interval;
      scheduleTimer(interval);
    } else {
      console.log(`[fixtures] next sync at ${nextSyncAt}`);
    }
  } catch (err) {
    // Errors are already recorded in the cache by service.syncFixtures().
    // Keep the timer alive — the retry happens on the next scheduled tick.
    console.error('[fixtures] scheduler error (will retry on next tick):', err.message);
    const nextSyncAt = new Date(Date.now() + NORMAL_INTERVAL_MS).toISOString();
    updateNextSync(nextSyncAt);
  } finally {
    syncing = false;
  }
}

function scheduleTimer(intervalMs) {
  if (timer) clearInterval(timer);
  timer = setInterval(() => runSync('scheduled'), intervalMs);
}

/** Start the scheduler (called once at boot). */
function startFixtureSync() {
  // Fire an immediate sync so the cache is warm before the first visitor.
  runSync('startup');

  const interval = NORMAL_INTERVAL_MS;
  lastScheduledIntervalMs = interval;
  const nextSyncAt = new Date(Date.now() + interval).toISOString();
  updateNextSync(nextSyncAt);
  scheduleTimer(interval);
}

/**
 * Refresh the cache if it has gone stale, triggered by a visitor's request
 * rather than by the timer.
 *
 * The setInterval scheduler above only runs while the Node process is alive.
 * On a host that sleeps the app when idle (e.g. Render's free tier), the
 * process — and its timer — is killed after a few minutes without traffic,
 * so overnight, when nobody is on the site, scheduled syncs simply never
 * happen and scores sit stale until someone shows up. This closes that gap:
 * whenever a page asks for fixture data and the cache is older than the
 * interval we'd have wanted, kick off a sync.
 *
 * Deliberately fire-and-forget — the caller's response is never delayed. The
 * page polls every 60s, so the fresh data lands moments later.
 */
function ensureFresh() {
  if (syncing) return;
  const now = Date.now();

  // Cooldown on ATTEMPTS, not just successes. A failing sync (rate limit,
  // API outage) leaves lastSync untouched, so without this every single
  // request would fire another attempt and hammer Football-Data.org.
  if (now - lastOnDemandAttempt < MATCHDAY_INTERVAL_MS) return;

  const cache = getCachedFixtures();
  const interval = desiredIntervalMs(cache);
  const lastSync = cache.lastSync ? new Date(cache.lastSync).getTime() : 0;
  if (now - lastSync < interval) return;

  lastOnDemandAttempt = now;
  runSync('stale-cache');
}

/** Manual "Sync Now" from the admin panel. */
async function syncNow() {
  const cache = await syncFixtures();
  const interval = desiredIntervalMs(cache);
  const nextSyncAt = new Date(Date.now() + interval).toISOString();
  updateNextSync(nextSyncAt);
  return getCachedFixtures();
}

/** Manual "Clear Cache" from the admin panel. */
function clearCache() {
  if (timer) clearInterval(timer);
  clearFixturesCache();
  // Reschedule immediately to refill the cache
  lastScheduledIntervalMs = NORMAL_INTERVAL_MS;
  scheduleTimer(NORMAL_INTERVAL_MS);
  runSync('after-clear');
  return getCachedFixtures();
}

module.exports = { startFixtureSync, syncNow, clearCache, ensureFresh };