-- Post URLs take the shape Google+ used:
--
--     /<profile id>/posts/<post id>    e.g. /105426468311954266553/posts/WU4Qec9X6os
--
-- Two identifiers are needed for that, and neither existed in the right shape: a
-- post was addressed only by its integer row id, and an account's public id was a
-- 16-character hex token rather than the 21-digit number the archived URLs show.
--
-- The previous profile id is kept in users.legacy_user_id instead of being
-- discarded, so this is reversible. It is not needed to keep old links working:
-- the app looks a post up by its own public id and treats the profile-id segment
-- as decoration, correcting a stale one with a redirect.
ALTER TABLE posts ADD COLUMN public_id TEXT;

-- Backfill in the same length and mixed case as a Google+ post id: four uppercase
-- and seven lowercase hex characters (new posts get full base62 ids from the app).
UPDATE posts
   SET public_id = substr(upper(hex(randomblob(2))) || lower(hex(randomblob(4))), 1, 11)
 WHERE public_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_posts_public_id ON posts(public_id);

ALTER TABLE users ADD COLUMN legacy_user_id TEXT;

UPDATE users SET legacy_user_id = user_id WHERE legacy_user_id IS NULL;

-- 21 random digits, built from two 19-digit randoms and trimmed, so the length is
-- always exactly 21 regardless of how small the random values came out.
UPDATE users
   SET user_id = substr(printf('%019d', abs(random())) || printf('%019d', abs(random())), 1, 21);
