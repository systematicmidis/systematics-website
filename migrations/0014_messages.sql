-- Messages, and the log of what moderation did and why.
--
-- Two tables, because they answer two different questions.
--
-- `messages` is the visitor's own inbox. A row is written to it by the site's
-- bot when something happens to the account (a ban, a lifted ban) and by an
-- admin when they want to say something to a person. Everything about the
-- message a reader could need is copied into the row rather than looked up
-- later: the snapshot columns (`about_*`) hold what the moderation was about,
-- so a notice still explains itself after the comment it names has been
-- deleted, and `ban_*` records the ban the notice describes so lifting that ban
-- can find the notice again (see send_ban_notice() and the notice/lift pair in
-- src/worker.py).
--
-- `sender_id` is NULL for the bot and holds the acting admin's row id when a
-- person wrote it; `sender_label` is the name shown either way, so a message
-- from an admin who later deletes their account does not lose its author.
--
-- `moderation_log` is the admins' side of the same events: one row per ban, per
-- lifted ban and per message sent, keeping `content_kind`/`content_id` of the
-- post or comment that caused it. It is a log rather than a column on `users`
-- because migration 0009's columns only remember the *last* ban - the log
-- remembers all of them, which is what the admin panel reads back.
--
-- Rows cascade with the account they belong to. Deleting an account is a soft
-- delete (see anonymise_account in src/worker.py), which also clears that
-- person's inbox, so in practice the cascade only fires if a row is ever hard
-- deleted.
--
-- Apply with `npm run db:remote` (production) or `npm run db:local` (local dev)
-- BEFORE the code that reads these tables is deployed: the rail badge, the
-- admin panel and the account row all read them defensively, so a database
-- without this migration shows no messages rather than failing to render.

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL,
    sender_id INTEGER,
    sender_label TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'note',
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    about_kind TEXT,
    about_id INTEGER,
    about_title TEXT,
    about_excerpt TEXT,
    about_url TEXT,
    ban_kind TEXT,
    ban_permanent INTEGER NOT NULL DEFAULT 0,
    ban_until TEXT,
    read_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(recipient_id, read_at);

CREATE TABLE IF NOT EXISTS moderation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    ban_kind TEXT,
    permanent INTEGER NOT NULL DEFAULT 0,
    until TEXT,
    reason TEXT,
    acted_by TEXT,
    content_kind TEXT,
    content_id INTEGER,
    content_title TEXT,
    content_excerpt TEXT,
    content_url TEXT,
    message_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_moderation_user ON moderation_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_moderation_recent ON moderation_log(created_at DESC);
