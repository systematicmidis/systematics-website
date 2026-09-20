-- Direct messages, the Hangouts way.
--
-- Migration 0014 made `messages` a one-way notice board: the site wrote to a
-- person and the person read it. Hangouts was a conversation, so the same table
-- now holds both halves of one, and a `conversations` row is the thread itself.
--
-- One row per pair of accounts, always stored with the smaller user id in
-- `user_low`, so two people can only ever have one thread no matter who writes
-- first (UNIQUE(user_low, user_high) enforces it). `last_message_at` is kept up
-- to date on every send, because the inbox orders threads by it.
--
-- Nothing about the message row changes: `sender_id` is who wrote it - for an
-- automatic notice, the SystematicsModeration account, which is what makes a
-- notice look like a message from a person rather than a disembodied label -
-- `recipient_id` is the other participant, and `read_at` is when that participant
-- read it, which is what Hangouts showed as "Seen". An unread count is therefore
-- just messages addressed to you with no read mark, per thread or in total.
--
-- `conversation_id` is deliberately nullable: a notice written when no moderation
-- account exists to write it has no thread to belong to, and the inbox still lists
-- those on their own (see standalone_notices() in src/worker.py). Migration 0014's
-- rows were exactly that shape, so the backfill below moves any that were written
-- before the account existed into the thread it would have used.
--
-- Apply with `npm run db:remote` (production) or `npm run db:local` (local dev)
-- BEFORE deploying the code that reads these tables.

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_low INTEGER NOT NULL,
    user_high INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_message_at TEXT,
    UNIQUE(user_low, user_high),
    FOREIGN KEY(user_low) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(user_high) REFERENCES users(id) ON DELETE CASCADE
);

-- The inbox reads "every thread I am in, newest first", which is one of these two
-- indexes depending on which side of the pair the reader happens to be.
CREATE INDEX IF NOT EXISTS idx_conversations_low ON conversations(user_low, last_message_at DESC);
CREATE INDEX IF NOT EXISTS idx_conversations_high ON conversations(user_high, last_message_at DESC);

ALTER TABLE messages ADD COLUMN conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);

-- Every existing notice was written by the site rather than by a person
-- (`sender_id IS NULL`), so each one belongs in a thread with the moderation
-- account. Both statements are guarded on that account existing: with no account
-- to thread them to, nobody is there to have written them, and they stay as they
-- are so the inbox can still show them.
INSERT OR IGNORE INTO conversations (user_low, user_high, last_message_at)
SELECT MIN(messages.recipient_id, (SELECT id FROM users WHERE username = 'SystematicsModeration')),
       MAX(messages.recipient_id, (SELECT id FROM users WHERE username = 'SystematicsModeration')),
       MAX(messages.created_at)
  FROM messages
 WHERE messages.sender_id IS NULL
   AND messages.recipient_id IS NOT NULL
   AND (SELECT id FROM users WHERE username = 'SystematicsModeration') IS NOT NULL
 GROUP BY messages.recipient_id;

UPDATE messages
   SET sender_id = (SELECT id FROM users WHERE username = 'SystematicsModeration'),
       sender_label = (SELECT display_name FROM users WHERE username = 'SystematicsModeration'),
       conversation_id = (
           SELECT conversations.id
             FROM conversations
            WHERE conversations.user_low = MIN(messages.recipient_id,
                                               (SELECT id FROM users WHERE username = 'SystematicsModeration'))
              AND conversations.user_high = MAX(messages.recipient_id,
                                                (SELECT id FROM users WHERE username = 'SystematicsModeration'))
       )
 WHERE messages.sender_id IS NULL
   AND messages.recipient_id IS NOT NULL
   AND messages.conversation_id IS NULL
   AND (SELECT id FROM users WHERE username = 'SystematicsModeration') IS NOT NULL;
