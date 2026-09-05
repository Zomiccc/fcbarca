/* ==========================================================================
   PREDICTOR LEAGUE — rules engine
   All the league's rules live here so they are enforced in exactly one place:

   1. WINDOW      Members predict one competition's round (matchday) at a
                  time — every fixture in that round, whichever competition
                  has the soonest upcoming fixture. Never mixes two rounds or
                  two competitions in one set, even if the current round is
                  down to its last unplayed fixture.
   2. DEADLINE    The whole set locks when the FIRST of those matches kicks off.
   3. IMMUTABLE   A prediction, once stored, is never changed by anyone. This
                  module never returns an "update" path, and the only write in
                  the app rejects duplicates. Admin has no edit route at all.
   4. PRIVACY     Another member's prediction is only ever exposed after that
                  match has kicked off. Filtering happens server-side.
   5. POINTS      Exact score = 3, correct result (W/D/L) = 1, wrong = 0.
   ========================================================================== */

const POINTS = {
  EXACT_SCORE: 3,
  CORRECT_RESULT: 1,
  WRONG: 0,
};

// A match is no longer predictable once it has kicked off, whatever the API
// status says (status can lag behind real kickoff time by a few minutes).
function hasKickedOff(match, now = new Date()) {
  return new Date(match.utcDate) <= now;
}

function isPlayable(match) {
  return !['POSTPONED', 'CANCELLED', 'SUSPENDED'].includes(match.status);
}

/**
 * The prediction set members currently see: every upcoming fixture in ONE
 * round of ONE competition — whichever competition/matchday has the soonest
 * upcoming fixture. Right now that's La Liga matchday 4; once every La Liga
 * matchday-4 fixture has kicked off, the soonest upcoming fixture becomes
 * matchday 5 (or the next Champions League round, whichever is sooner) and
 * the set switches over to it automatically.
 *
 * Deliberately never backfills with fixtures from a different round to pad
 * the set out to some fixed size — as matchday-4 fixtures kick off one by
 * one, the set simply shrinks to whatever's left in matchday 4 rather than
 * pulling in matchday-5 fixtures early.
 */
function getPredictionWindow(matches, now = new Date()) {
  const upcoming = (matches || [])
    .filter((m) => isPlayable(m) && !hasKickedOff(m, now))
    .sort((a, b) => new Date(a.utcDate) - new Date(b.utcDate));

  if (!upcoming.length) return [];

  const soonest = upcoming[0];
  const competitionKey = soonest.competitionId || soonest.competition;
  // `upcoming` is already sorted soonest-first, and .filter() preserves
  // relative order, so no re-sort is needed after this.
  return upcoming.filter(
    (m) => (m.competitionId || m.competition) === competitionKey && m.matchday === soonest.matchday,
  );
}

/** Time wasted here = 2 Hours! If u are a dev and encountring this english guy just to let yk u will receive a fucking ton of changes for no fucking reason
 * The submission deadline: kickoff of the soonest upcoming match. Once this
 * passes, the current set is closed (a new set — and a new deadline — opens as
 * the window rolls forward).
 */
function getDeadline(matches, now = new Date()) {
  const window = getPredictionWindow(matches, now);
  return window.length ? new Date(window[0].utcDate) : null;
}

/** 'HOME' | 'AWAY' | 'DRAW' for any home/away goal pair. */
function outcome(homeGoals, awayGoals) {
  if (homeGoals > awayGoals) return 'HOME';
  if (homeGoals < awayGoals) return 'AWAY';
  return 'DRAW';
}

/**
 * @param {object} match
 * @param {string|null} [lastSyncIso] ISO timestamp of the last successful
 *   fixture sync (data/fixtures.json's `lastSync`). Required to safely use
 *   the bogus-status fallback below — see its comment for why.
 */
function hasFinalScore(match, lastSyncIso) {
  if (
    match &&
    match.status === 'FINISHED' &&
    Number.isInteger(match.score?.home) &&
    Number.isInteger(match.score?.away)
  ) {
    return true;
  }
  // Belt-and-braces: if the API gave us a bogus status but the match kicked
  // off long ago and we have integer scores, treat it as finished. The
  // 3-hour window covers extra time + penalties + slight API delays.
  //
  // This is ONLY safe if we've actually re-synced with Football-Data.org
  // some time after that 3-hour mark. Without that check, a match whose
  // cache simply hasn't refreshed in a while (a missed sync, the host being
  // asleep, a rate limit) would have its LAST KNOWN score — which could be
  // a mid-match snapshot, e.g. the halftime score — wrongly locked in as the
  // final result, scoring every prediction against a scoreline the match
  // never actually ended on.
  if (
    match &&
    match.utcDate &&
    Number.isInteger(match.score?.home) &&
    Number.isInteger(match.score?.away) &&
    !['SCHEDULED', 'TIMED', 'POSTPONED', 'CANCELLED', 'SUSPENDED'].includes(match.status)
  ) {
    const presumedFinishTime = new Date(match.utcDate).getTime() + 3 * 60 * 60 * 1000;
    if (presumedFinishTime > Date.now()) return false;
    if (!lastSyncIso) return false;
    return new Date(lastSyncIso).getTime() >= presumedFinishTime;
  }
  return false;
}

/**
 * Points for a single prediction against a finished match.
 * Returns 0 for matches that aren't finished yet (nothing to score).
 */
function scorePrediction(prediction, match, lastSyncIso) {
  if (!hasFinalScore(match, lastSyncIso)) return 0;
  const actualHome = match.score.home;
  const actualAway = match.score.away;

  if (prediction.homeGoals === actualHome && prediction.awayGoals === actualAway) {
    return POINTS.EXACT_SCORE;
  }
  if (outcome(prediction.homeGoals, prediction.awayGoals) === outcome(actualHome, actualAway)) {
    return POINTS.CORRECT_RESULT;
  }
  return POINTS.WRONG;
}

/** Human-readable label for how a prediction scored — used in the UI. */
function scoreLabel(points) {
  if (points === POINTS.EXACT_SCORE) return 'Exact score';
  if (points === POINTS.CORRECT_RESULT) return 'Correct result';
  return 'Wrong result';
}

/**
 * Build the league table. One row per member who has predicted at least one
 * match IN THIS COMPETITION, sorted by total points (then exact-score count,
 * then name) so ties break sensibly.
 *
 * @param {string} [competitionCode] Restrict to one competition (e.g. 'PD'
 *   for La Liga, 'CL' for the Champions League) — the club runs a separate
 *   table per competition, so a member's Champions League picks never affect
 *   their La Liga standing or vice versa. Omit to combine every competition
 *   into one table (kept for callers that still want that).
 */
function buildLeaderboard(predictions, members, matches, lastSyncIso, competitionCode) {
  const matchById = new Map((matches || []).map((m) => [String(m.id), m]));
  const memberById = new Map((members || []).map((m) => [m.id, m]));
  const rows = new Map();

  for (const p of predictions || []) {
    const member = memberById.get(p.memberId);
    if (!member) continue; // member record removed — skip rather than crash

    const match = matchById.get(String(p.fixtureId));
    if (competitionCode && match?.competitionCode !== competitionCode) continue;

    if (!rows.has(p.memberId)) {
      rows.set(p.memberId, {
        memberId: p.memberId,
        name: `${member.firstName} ${member.lastName}`.trim(),
        points: 0,
        played: 0,
        exact: 0,
        correctResult: 0,
        predictionsMade: 0,
      });
    }
    const row = rows.get(p.memberId);
    row.predictionsMade += 1;

    if (!hasFinalScore(match, lastSyncIso)) continue;

    const pts = scorePrediction(p, match, lastSyncIso);
    row.points += pts;
    row.played += 1;
    if (pts === POINTS.EXACT_SCORE) row.exact += 1;
    else if (pts === POINTS.CORRECT_RESULT) row.correctResult += 1;
  }

  return [...rows.values()]
    .sort((a, b) => b.points - a.points || b.exact - a.exact || a.name.localeCompare(b.name))
    .map((row, i) => ({ ...row, rank: i + 1 }));
}

module.exports = {
  POINTS,
  hasKickedOff,
  isPlayable,
  getPredictionWindow,
  getDeadline,
  outcome,
  hasFinalScore,
  scorePrediction,
  scoreLabel,
  buildLeaderboard,
};
