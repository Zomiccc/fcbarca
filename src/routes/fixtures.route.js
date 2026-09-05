/* ==========================================================================
   FIXTURES ROUTES
   Public + admin endpoints for the cached Barcelona fixture data.

   IMPORTANT: These routes NEVER call Football-Data.org. They only read from
   data/fixtures.json (populated by the scheduler in src/jobs/fixtureSync.job.js).
   ========================================================================== */
const express = require("express");
const {
  getCachedFixtures,
  getFixtureResult,
  overrideMatchResult,
} = require("../services/fixture.service");
const { syncNow, clearCache, ensureFresh } = require("../jobs/fixtureSync.job");

/**
 * Build the fixtures router.
 * @param {Function} requireAdmin  Express middleware from server.js that
 *                                 guards admin-only routes with a session cookie.
 */
function buildFixturesRouter(requireAdmin) {
  const router = express.Router();

  /**
   * GET /api/fixtures
   * Public — returns the cached fixture list (Barça matches only).
   * Other matches are stored in the cache for the predictor but not shown
   * on the public fixtures page.
   * Never touches Football-Data.org.
   */
  router.get("/api/fixtures", (req, res) => {
    ensureFresh();
    const data = getCachedFixtures();
    res.json({
      ...data,
      matches: (data.matches || []).filter((m) => m.isBarcaMatch),
    });
  });

  /**
   * GET /api/fixtures/next
   * Public — convenience endpoint for the homepage "Next Match" section.
   * Returns the single soonest upcoming fixture (or null).
   */
  router.get("/api/fixtures/next", (req, res) => {
    ensureFresh();
    const data = getCachedFixtures();
    const now = new Date();
    const upcoming = (data.matches || [])
      .filter(
        (m) =>
          m.isBarcaMatch &&
          new Date(m.utcDate) > now &&
          !["FINISHED", "POSTPONED", "CANCELLED"].includes(m.status),
      )
      .sort((a, b) => new Date(a.utcDate) - new Date(b.utcDate));
    res.json({
      ...data,
      next: upcoming[0] || null,
    });
  });
/**
 * GET /api/fixtures/:id/result
 * Public — fetches the latest result for one fixture.
 */
router.get(
  '/api/fixtures/:id/result',
  async (req, res) => {
    try {
      const fixtureId =
        Number(req.params.id);

      if (
        !Number.isInteger(
          fixtureId
        ) ||
        fixtureId <= 0
      ) {
        return res
          .status(400)
          .json({
            error:
              'Invalid fixture id',
          });
      }

      const result =
        await getFixtureResult(
          fixtureId
        );

      res.json(result);
    } catch (err) {
      console.warn(
        '[fixtures] result lookup failed:',
        err.message
      );

      res.status(502).json({
        error:
          'Could not fetch match result.',
      });
    }
  }
);
  /**
   * GET /api/admin/fixtures/status
   * Admin — sync status for the dashboard (last sync, next sync, count, API status).
   */
  router.get("/api/admin/fixtures/status", requireAdmin, (req, res) => {
    const data = getCachedFixtures();
    res.json({
      lastSync: data.lastSync,
      nextSync: data.nextSync,
      count: (data.matches || []).length,
      apiStatus: data.apiStatus,
      lastError: data.lastError,
    });
  });

  /**
   * POST /api/admin/fixtures/sync
   * Admin — force an immediate sync with Football-Data.org.
   */
  router.post("/api/admin/fixtures/sync", requireAdmin, async (req, res) => {
    try {
      const data = await syncNow();
      res.json({ ok: true, ...data });
    } catch (err) {
      res.status(502).json({ error: err.message });
    }
  });

  /**
   * POST /api/admin/fixtures/clear
   * Admin — wipe the cache (the scheduler refills it immediately).
   */
  router.post("/api/admin/fixtures/clear", requireAdmin, (req, res) => {
    const data = clearCache();
    res.json({ ok: true, ...data });
  });

  /**
   * POST /api/admin/fixtures/override
   * Admin — manually override a match's status and score in the cache.
   * Used when the Football-Data API returns wrong/stale data.
   * Body: { fixtureId, status, homeScore, awayScore }
   */
  router.post("/api/admin/fixtures/override", requireAdmin, (req, res) => {
    const { fixtureId, status, homeScore, awayScore } = req.body || {};
    if (!fixtureId || !status) {
      return res.status(400).json({ error: "fixtureId and status are required" });
    }
    const validStatuses = ["TIMED", "IN_PLAY", "FINISHED", "POSTPONED", "CANCELLED", "SUSPENDED"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${validStatuses.join(", ")}` });
    }
    const match = overrideMatchResult(fixtureId, status, homeScore, awayScore);
    if (!match) {
      return res.status(404).json({ error: "Match not found in cache" });
    }
    res.json({ ok: true, match: { id: match.id, homeTeam: match.homeTeam, awayTeam: match.awayTeam, status: match.status, score: match.score } });
  });

  return router;
}

module.exports = { buildFixturesRouter };
