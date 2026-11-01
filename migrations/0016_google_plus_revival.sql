-- Google+ revival -------------------------------------------------------------
-- Everything the 2016 product had that this site did not: circles and the
-- audience selector, collections, communities, events, notifications, +1s on
-- comments, reshares, photo posts, tags, blocks, mutes, reports, and the profile
-- fields G+ put between the name and the stream.
--
-- Idempotent where SQLite allows it (CREATE ... IF NOT EXISTS). The ALTERs are
-- not, because SQLite has no ADD COLUMN IF NOT EXISTS; the migration runner
-- records what it has run, so each one executes exactly once.

-- Circles ----------------------------------------------------------------------
-- A circle is a named group of the people one account follows. It is private to
-- its owner: nobody is told which circle they are in, which was the point of the
-- thing, and a post shared to a circle names the circle only to its author.
CREATE TABLE IF NOT EXISTS circles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS circle_members (
    circle_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (circle_id, user_id),
    FOREIGN KEY (circle_id) REFERENCES circles(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Collections ------------------------------------------------------------------
-- A topic sub-feed of one account's own posts: "Armageddon", "Tutorials".
CREATE TABLE IF NOT EXISTS collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Communities ------------------------------------------------------------------
-- A space with members and its own stream, the way a G+ community worked. The
-- owner is the account that made it; moderators are members with a role.
CREATE TABLE IF NOT EXISTS communities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    owner_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS community_members (
    community_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (community_id, user_id),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Events -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    starts_at TEXT NOT NULL,
    location TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS event_attendees (
    event_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'going',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id, user_id),
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Posts gain an audience, a home in a collection/community/event, the two
-- moderator switches G+ called "pin" and "lock", a content warning, and the post
-- a share was made from.
ALTER TABLE posts ADD COLUMN audience TEXT NOT NULL DEFAULT 'public';
ALTER TABLE posts ADD COLUMN circle_id INTEGER;
ALTER TABLE posts ADD COLUMN collection_id INTEGER;
ALTER TABLE posts ADD COLUMN community_id INTEGER;
ALTER TABLE posts ADD COLUMN event_id INTEGER;
ALTER TABLE posts ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN locked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN content_warning TEXT;
ALTER TABLE posts ADD COLUMN share_of INTEGER;

-- Notifications ----------------------------------------------------------------
-- One row per thing worth telling somebody about. `kind` is what happened, the
-- actor is who did it, and the post/comment are there to link back and to let
-- the page read the sentence it needs without another lookup.
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    actor_id INTEGER,
    post_id INTEGER,
    comment_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (user_id, id DESC);

-- +1 on comments ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS comment_votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    value INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (comment_id, user_id),
    FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_comment_votes_comment ON comment_votes (comment_id);

-- Photos -----------------------------------------------------------------------
-- Uploaded images already live in `uploads`; this is the join that puts them in
-- a post, in order. Files are deleted from `uploads` when the post goes.
CREATE TABLE IF NOT EXISTS post_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_post_images_post ON post_images (post_id, position);

-- People tagged in a post's photos, which is what puts it on their profile under
-- "Photos of you".
CREATE TABLE IF NOT EXISTS post_people (
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Hashtags ---------------------------------------------------------------------
-- Stored on write so a tag page and the trending strip are one query instead of
-- a scan through every post body.
CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (post_id, tag),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_post_tags_tag ON post_tags (tag, post_id);

-- Reshares ---------------------------------------------------------------------
-- A reshare is kept in `shares` for counting and for "who shared this", while
-- the share itself is a post row with `share_of` set - so it flows through the
-- feed, profiles and pagination exactly like anything else.
CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    post_id_created INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_shares_post ON shares (post_id);

-- Blocking, muting and reports --------------------------------------------------
-- A block is mutual invisibility: feeds, follows and messages all consult it.
CREATE TABLE IF NOT EXISTS blocks (
    blocker_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (blocker_id, blocked_id),
    FOREIGN KEY (blocker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Muting a post stops its notifications without hiding it.
CREATE TABLE IF NOT EXISTS post_mutes (
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER,
    kind TEXT NOT NULL,
    post_id INTEGER,
    comment_id INTEGER,
    target_user_id INTEGER,
    reason TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,
    resolved_by TEXT,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Profile fields -----------------------------------------------------------------
-- What G+ showed in the About card, plus the "bragging rights" line. They are
-- free text rather than enumerations: a small site has no use for validating
-- somebody's relationship status, and G+ let people write anything anyway.
ALTER TABLE users ADD COLUMN tagline TEXT;
ALTER TABLE users ADD COLUMN nickname TEXT;
ALTER TABLE users ADD COLUMN about_work TEXT;
ALTER TABLE users ADD COLUMN about_education TEXT;
ALTER TABLE users ADD COLUMN about_places TEXT;
ALTER TABLE users ADD COLUMN about_relationship TEXT;
ALTER TABLE users ADD COLUMN about_birthday TEXT;
ALTER TABLE users ADD COLUMN about_gender TEXT;
ALTER TABLE users ADD COLUMN about_contact TEXT;
ALTER TABLE users ADD COLUMN bragging_rights TEXT;
ALTER TABLE users ADD COLUMN cover_position TEXT;
ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;
