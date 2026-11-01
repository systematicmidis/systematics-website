-- Hangouts, account recovery, and the rest of Google+ --------------------------
-- Everything the 2019 product still had that this site did not: group Hangouts
-- with attachments and calls, communities with categories, branding, join
-- approval and moderation, followable Pages with insights, editable events with
-- invitations and calendar export, scheduled posts, polls, share-to-circle,
-- post edit history, comment images, tag follows, and the account tools that
-- keep a real signup usable (password reset, email verification, two-factor
-- auth, sign out everywhere).
--
-- As with 0016 and 0017, every read is gated on gplus3_schema(), so a code
-- deploy that lands before this migration keeps the old site working.

-- Account recovery and sessions ------------------------------------------------
ALTER TABLE users ADD COLUMN email_verified_at TEXT;
-- Bumped by "sign out everywhere"; a cookie carrying an older value is refused.
ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
-- Base32 TOTP secret, and the SHA-256 hashes of the recovery codes (one JSON
-- array) so a lost phone still has a way back in.
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_recovery TEXT;
-- Which part of the avatar the circle should show: center, top or bottom.
ALTER TABLE users ADD COLUMN avatar_position TEXT;

-- One row per reset request. Only the hash of the emailed token is stored, so a
-- database read cannot be turned into a working reset link.
CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets (user_id, id DESC);

CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications (user_id, id DESC);

-- Communities -------------------------------------------------------------------
ALTER TABLE communities ADD COLUMN category TEXT;
ALTER TABLE communities ADD COLUMN avatar TEXT;
ALTER TABLE communities ADD COLUMN banner TEXT;
ALTER TABLE communities ADD COLUMN rules TEXT;
-- open = join immediately; approval = a moderator decides; invite = only a
-- moderator can add somebody.
ALTER TABLE communities ADD COLUMN join_policy TEXT NOT NULL DEFAULT 'open';
ALTER TABLE community_members ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

CREATE INDEX IF NOT EXISTS idx_community_members_status
    ON community_members (community_id, status);

-- Pages -------------------------------------------------------------------------
ALTER TABLE pages ADD COLUMN category TEXT;
ALTER TABLE pages ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS page_follows (
    page_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (page_id, user_id),
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_page_follows_user ON page_follows (user_id, page_id);

-- Events ------------------------------------------------------------------------
ALTER TABLE events ADD COLUMN cover TEXT;
ALTER TABLE events ADD COLUMN community_id INTEGER;
ALTER TABLE events ADD COLUMN updated_at TEXT;

CREATE TABLE IF NOT EXISTS event_invites (
    event_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    invited_by INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id, user_id),
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Hangout rooms -----------------------------------------------------------------
ALTER TABLE hangouts ADD COLUMN scheduled_at TEXT;
ALTER TABLE hangouts ADD COLUMN conversation_id INTEGER;
ALTER TABLE hangouts ADD COLUMN chat_id INTEGER;

CREATE TABLE IF NOT EXISTS hangout_invites (
    hangout_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    invited_by INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (hangout_id, user_id),
    FOREIGN KEY (hangout_id) REFERENCES hangouts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Posts: scheduling, polls, revisions, comment images, tag follows --------------
ALTER TABLE posts ADD COLUMN publish_at TEXT;
ALTER TABLE posts ADD COLUMN community_pinned INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS post_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    edited_by INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (edited_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_post_revisions_post ON post_revisions (post_id, id DESC);

CREATE TABLE IF NOT EXISTS polls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL UNIQUE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS poll_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_poll_options_poll ON poll_options (poll_id, position);

CREATE TABLE IF NOT EXISTS poll_votes (
    poll_id INTEGER NOT NULL,
    option_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (poll_id, user_id),
    FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE,
    FOREIGN KEY (option_id) REFERENCES poll_options(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS comment_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_comment_images_comment ON comment_images (comment_id, position);

CREATE TABLE IF NOT EXISTS tag_follows (
    user_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, tag),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tag_follows_tag ON tag_follows (tag, user_id);

-- Group Hangouts ----------------------------------------------------------------
-- The 2019 product's chat was not only one-to-one. A group is its own thread;
-- the old `conversations` table keeps serving two-person DMs unchanged, and a
-- message belongs to exactly one of them (`conversation_id` or `chat_id`).
CREATE TABLE IF NOT EXISTS chat_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_message_at TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_members (
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_read_at TEXT,
    PRIMARY KEY (chat_id, user_id),
    FOREIGN KEY (chat_id) REFERENCES chat_threads(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id, chat_id);

-- A message's `recipient_id` stays NOT NULL: in a group it is the sender's own
-- id, because a group message is not addressed to one person. Unread state for a
-- group lives on chat_members.last_read_at instead.
ALTER TABLE messages ADD COLUMN chat_id INTEGER;
ALTER TABLE messages ADD COLUMN attachment TEXT;
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages (chat_id, id);

-- A notification now points somewhere more specific than "the post" or "the
-- person": a community, an event, a Hangout room. The link is stored when the
-- notification is written so the bell does not need a join per kind.
ALTER TABLE notifications ADD COLUMN link TEXT;
