-- Serve uploaded images (avatars, banners) out of D1 instead of R2.
--
-- R2 is the natural home for blobs, but enabling it requires completing an R2
-- subscription checkout. D1 is included on the Workers Free plan with no
-- payment method, so the whole site can run for free. The trade-off is D1's
-- 2 MB per-row limit, which src/worker.py enforces before inserting.
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL UNIQUE,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
