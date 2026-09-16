-- Rich link cards for posts that contain a URL (what Discord/Slack embeds show).
--
-- posts.link_url   the first web link found in a post's body, set when the post is
--                  saved by src/worker.py.
-- link_previews    one cached card per URL: the title, description, image and site
--                  parsed out of that page's Open Graph tags.
--
-- The card is fetched and stored when the post is written, never while a page is
-- being rendered: the Workers Free plan budgets 10 ms of CPU per request, and
-- waiting on somebody else's web server during a feed render would blow through it.
-- Rows whose title/image are both NULL record "no card available" so a dead or
-- unhelpful link is not re-fetched on every page view.

ALTER TABLE posts ADD COLUMN link_url TEXT;

CREATE TABLE IF NOT EXISTS link_previews (
    url TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    image TEXT,
    site TEXT,
    fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_posts_link_url ON posts (link_url);
