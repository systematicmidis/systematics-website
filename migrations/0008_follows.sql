-- Followers, the thing a Google+-style profile is built around.
--
-- follows    one row per directed relationship, so following is one-way and can be
--            mutual without a second table. The composite primary key is what makes
--            following somebody twice impossible: SQLite rejects the duplicate rather
--            than relying on the application to check first. Both foreign keys cascade,
--            so deleting an account cannot leave rows pointing at a missing user.
--
-- The two indexes cover the only questions asked of this table - "who follows me" and
-- "who do I follow" - both newest first, which is how the lists are shown.

CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL,
    followed_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (follower_id, followed_id),
    FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(followed_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_follows_followed ON follows (followed_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows (follower_id, created_at DESC);
