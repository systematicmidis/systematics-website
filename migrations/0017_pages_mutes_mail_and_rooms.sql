-- The rest of Google+ ---------------------------------------------------------
-- Everything the revival still lacked: muting a person, per-type notification
-- preferences, an email outbox and digest, Pages (brand accounts), named photo
-- albums, Hangouts rooms, and Sparks (interest feeds of outside links).
--
-- As with migration 0016, the code reads these only when the migration is
-- present (gplus2_schema()), because the GitHub Action ships code and never
-- migrations.

-- Muting a person --------------------------------------------------------------
-- Softer than a block: their posts leave your streams and they stop notifying
-- you, but their profile still opens and messages are unaffected.
CREATE TABLE IF NOT EXISTS user_mutes (
    muter_id INTEGER NOT NULL,
    muted_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (muter_id, muted_id),
    FOREIGN KEY (muter_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (muted_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Notification preferences and email -------------------------------------------
-- notification_prefs is a JSON object of booleans keyed by notification kind
-- (see NOTIFICATION_KINDS). Missing keys mean "on", so an account created before
-- preferences existed keeps every notification.
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN notification_prefs TEXT;
-- 0 = in-app only, 1 = also queue a digest email when one is due.
ALTER TABLE users ADD COLUMN email_digest INTEGER NOT NULL DEFAULT 0;

-- Email is queued, never sent inside the request that caused it: a Worker has a
-- small CPU budget and an outbound provider can be slow. An admin (or a scheduled
-- task, if one is ever wired up) flushes the queue through EMAIL_API_URL.
CREATE TABLE IF NOT EXISTS email_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER,
    to_address TEXT NOT NULL,
    kind TEXT,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    sent_at TEXT,
    error TEXT,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email_outbox_pending
    ON email_outbox (sent_at, id);

-- Pages ------------------------------------------------------------------------
-- A brand identity that people manage instead of sign in as. A page can write
-- posts; those posts show the page's name and avatar, and open on the page's own
-- stream. Pages do not have their own sessions, so the manager stays the author
-- of record for moderation.
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    tagline TEXT,
    about TEXT,
    avatar TEXT,
    banner TEXT,
    owner_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS page_managers (
    page_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'manager',
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (page_id, user_id),
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE posts ADD COLUMN page_id INTEGER;

-- Albums ------------------------------------------------------------------------
-- A named group of one account's photo posts, the way a G+ album gathered the
-- photos from several posts. album_posts is many-to-many so one post can sit in
-- more than one album.
CREATE TABLE IF NOT EXISTS albums (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS album_posts (
    album_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (album_id, post_id),
    FOREIGN KEY (album_id) REFERENCES albums(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

-- Hangouts ----------------------------------------------------------------------
-- A room is a free Jitsi meeting on meet.jit.si, embedded on the hangout page: no
-- relay, account or payment method is involved. `kind` is 'hangout' or 'onair'
-- (a public room with an optional YouTube live embed).
CREATE TABLE IF NOT EXISTS hangouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    room TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'hangout',
    youtube_url TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    ended_at TEXT,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sparks -------------------------------------------------------------------------
-- A topic with a feed of outside links people add to it. Cards are built from the
-- target page's Open Graph tags through the same link_previews cache posts use, so
-- the page never waits on a third-party site at read time.
CREATE TABLE IF NOT EXISTS sparks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT,
    created_by INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS spark_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    spark_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    note TEXT,
    added_by INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (spark_id, url),
    FOREIGN KEY (spark_id) REFERENCES sparks(id) ON DELETE CASCADE,
    FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_spark_links_spark ON spark_links (spark_id, id DESC);
