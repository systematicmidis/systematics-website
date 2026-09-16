-- Posts are addressed by id (/post/<id>) instead of a slug, so the slug column
-- is dropped.
--
-- SQLite cannot drop a UNIQUE column in place, and dropping "posts" while
-- "comments" still holds a foreign key to it would cascade-delete every comment.
-- The tables are therefore rebuilt and swapped in the order below: comments is
-- moved to a table that points at the new posts table first, so by the time the
-- old posts table is dropped nothing references it. Renaming the new posts table
-- back to "posts" rewrites the foreign key in the new comments table for us.
CREATE TABLE posts_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'published',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO posts_new (id, title, content, status, created_at)
SELECT id, title, content, status, created_at FROM posts;

CREATE TABLE comments_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts_new(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO comments_new (id, post_id, user_id, content, created_at)
SELECT id, post_id, user_id, content, created_at FROM comments;

DROP TABLE comments;
DROP TABLE posts;

ALTER TABLE posts_new RENAME TO posts;
ALTER TABLE comments_new RENAME TO comments;

CREATE INDEX IF NOT EXISTS idx_posts_status_created ON posts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at);
CREATE INDEX IF NOT EXISTS idx_comments_user ON comments(user_id, created_at DESC);
