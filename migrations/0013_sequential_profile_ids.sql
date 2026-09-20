-- An account's public id becomes its place in the signup order: 1, 2, 3, ...
--
-- Migration 0012 reissued every id as a random 21-digit number, the shape
-- plus.google.com used (105426468311954266553 was somebody else's account id, not
-- part of the post). A number that long is noise in a URL, and nothing about it
-- is worth reading, so it is replaced by a short one that is: the first account
-- on the site is 1, the next 2, and so on.
--
-- The number is assigned in ``id`` order, which is the order the accounts were
-- created in (AUTOINCREMENT never reuses a row id). Every row gets a number,
-- including the tombstone rows left by a deleted account, so that deleting an
-- account never renumbers the people who stayed: numbers are stable for good
-- and a gap in the sequence simply means a member left.
--
-- The 21-digit value is dropped rather than kept. users.legacy_user_id still
-- holds the *original* 16-character id from before 0012, so nothing older than
-- the previous migration is lost.
--
-- New accounts continue the sequence in src/worker.py (next_profile_id), taking
-- one past the highest number in use.
UPDATE users
   SET user_id = (
        SELECT CAST(COUNT(*) AS TEXT) FROM users AS earlier WHERE earlier.id <= users.id
   );
