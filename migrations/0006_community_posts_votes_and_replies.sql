-- Community posting, post categories, likes/dislikes and comment replies.
--
-- posts.user_id   the account that wrote the post; NULL means "the site" (only the
--                 original seeded welcome post, until an owner account exists).
-- posts.category  'systematics' for posts written by a site owner account,
--                 'community' for everybody else. Set on write by src/worker.py.
-- comments.parent_id  the comment being replied to; replies render one level deep
--                 inside their thread.
-- post_votes      one row per (post, user) so a like can be switched to a dislike
--                 or removed again.

ALTER TABLE posts ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE posts ADD COLUMN category TEXT NOT NULL DEFAULT 'community';
ALTER TABLE comments ADD COLUMN parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS post_votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    value INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_posts_category ON posts (category, created_at);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments (post_id, created_at);
CREATE INDEX IF NOT EXISTS idx_post_votes_post ON post_votes (post_id);

-- The welcome post should belong to the owner account when one already exists. On a
-- fresh install it does not exist yet, so register() hands authorless posts to the
-- first owner account that signs up (see src/worker.py).
UPDATE posts
   SET user_id = (SELECT id FROM users WHERE username = 'SystematicMIDIS' COLLATE NOCASE),
       category = 'systematics'
 WHERE user_id IS NULL
   AND (SELECT id FROM users WHERE username = 'SystematicMIDIS' COLLATE NOCASE) IS NOT NULL;
