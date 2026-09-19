-- Account deletion and moderation bans.
--
-- Deleting an account is a soft delete, so a `deleted_at` marker is all the row
-- needs: the display name is rewritten to "[ Account Deleted ]", the username is
-- released as deleted_user_<id>, and the password hash, bio, avatar and banner
-- are cleared in the same statement (see anonymise_account() in src/worker.py).
-- The row survives because the posts and comments the person wrote point at it.
--
-- Bans are three independent kinds - account, comment, post - and each kind is
-- either temporary or permanent, which is why every kind gets two columns: an
-- expiry and a flag. Nothing sweeps expired bans; a ban whose expiry has passed
-- simply stops counting the next time it is read (see ban_state() in src/worker.py).
--
-- `ban_reason`, `banned_at` and `banned_by` record the last ban handed out, so
-- the admin panel can show why an account is restricted and who did it.
--
-- Note: these are ADD COLUMN statements, so unlike the earlier migrations this
-- one is not re-runnable by hand - wrangler records it as applied. Apply it with
-- `npm run db:remote` (production) or `npm run db:local` (local dev) BEFORE the
-- code that reads these columns is deployed, which is why the admin page and the
-- owner panel read them defensively.

ALTER TABLE users ADD COLUMN deleted_at TEXT;
ALTER TABLE users ADD COLUMN account_ban_until TEXT;
ALTER TABLE users ADD COLUMN account_ban_permanent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN comment_ban_until TEXT;
ALTER TABLE users ADD COLUMN comment_ban_permanent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN post_ban_until TEXT;
ALTER TABLE users ADD COLUMN post_ban_permanent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN ban_reason TEXT;
ALTER TABLE users ADD COLUMN banned_at TEXT;
ALTER TABLE users ADD COLUMN banned_by TEXT;
