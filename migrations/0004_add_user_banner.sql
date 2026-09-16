-- Custom profile banners.
--
-- `banner` holds the filename of an image in the BUCKET R2 bucket, served by
-- the /uploads/<filename> route. NULL means "use the default gradient".
ALTER TABLE users ADD COLUMN banner TEXT;
