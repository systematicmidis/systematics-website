-- Behind a post's [COMMITS] token: the repository's newest commits, shown one
-- line each.
--
-- Two tables rather than one. `commit_log` is a copy of what GitHub last told
-- us, so rendering an update-log post never waits on GitHub. `commit_sync` is a
-- single row recording when we last *asked*, which is what stops a Worker that
-- is being rate-limited from asking again on every page render - see
-- refresh_commit_log() in src/worker.py.
CREATE TABLE IF NOT EXISTS commit_log (
  -- GitHub's commit id. The primary key is what makes re-reading the same
  -- commit an update instead of a duplicate line.
  sha TEXT PRIMARY KEY,
  message TEXT NOT NULL,
  -- Stored the way every other timestamp in this database is ('YYYY-MM-DD
  -- HH:MM:SS', UTC), so the post's own date handling renders it unchanged.
  committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commit_sync (
  -- One row for the whole site, enforced: "when did we last ask GitHub" is not
  -- a per-commit fact. id = 1 is the only row this ever holds.
  id INTEGER PRIMARY KEY CHECK (id = 1),
  attempted_at TEXT NOT NULL,
  -- 1 only when the most recent attempt actually returned commits, which is
  -- what picks between the normal refresh interval and the longer one used
  -- after a failure.
  succeeded INTEGER NOT NULL DEFAULT 0
);
