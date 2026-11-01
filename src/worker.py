"""Flask application running on Cloudflare Workers (Python Workers).

Everything is driven by `pywrangler` (see README.md):

    uv run pywrangler dev      # local dev server, local D1
    uv run pywrangler deploy   # deploy to the Cloudflare network

Bindings/values declared in wrangler.jsonc:
    DB               D1 database (users, posts, comments, uploaded images)
    ASSETS           Workers static assets from ./public/
    SESSION_SECRET   Flask session signing key (secret)
    ADMIN_PASSWORD   Password for /admin/login (secret)

Uploaded images are stored as BLOB rows in the D1 `uploads` table rather than
in R2, so the site runs entirely on the Workers Free plan - enabling R2 requires
a subscription checkout, D1 does not.
"""
import hashlib
import hmac
import html
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import string
import struct
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request,
    session, url_for,
)
from flask.sessions import SecureCookieSessionInterface
from markupsafe import Markup
from pyodide.ffi import run_sync, to_js as _to_js
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from workers import wsgi

# JavaScript globals are looked up inside the functions that need them instead
# of being imported at module scope. Holding live JS proxies in module globals
# makes the deploy-time snapshot carry them, and rehydrating one on isolate
# start failed roughly half the time in production with
#
#   NoGilError: Attempted to use PyProxy when Python GIL not held
#
# thrown from preparePython() before any application code ran (Error 1101 on
# about half of all requests, including /static/*). Looking them up per call
# keeps every module global a plain Python value.
def js_object_from_entries():
    from js import Object
    return Object.fromEntries


def webcrypto_subtle():
    from js import crypto
    return crypto.subtle


def to_js(obj):
    """Turn Python dictionaries/lists into plain JavaScript objects."""
    return _to_js(obj, dict_converter=js_object_from_entries())


def find_template_dir():
    """Locate the bundled Jinja templates.

    Wrangler uploads everything under src/ alongside the Worker, but the
    runtime working directory is not guaranteed, so probe the plausible
    locations and fall back to this file's own directory.
    """
    here = Path(__file__).resolve().parent
    candidates = [here / "templates", Path("templates"), Path("src") / "templates"]
    for candidate in candidates:
        try:
            if (candidate / "base.html").is_file():
                return candidate
        except OSError:
            continue
    return candidates[0]


TEMPLATE_DIR = find_template_dir()

app = Flask(__name__, template_folder=str(TEMPLATE_DIR), static_folder=None)

# Upload limits. D1 caps a row (and therefore an image) at 2 MB, and MAX_IMAGE_BYTES
# stays under that with room for the other columns. MAX_CONTENT_LENGTH is only a
# backstop for absurd request bodies; valid-but-too-big images get a flash message
# from the per-image check instead of a bare 413. Images near the cap cost roughly
# a second of CPU to accept on the Free plan (see save_image_upload), so this is
# deliberately a little under the D1 row limit rather than right at it.
MAX_IMAGE_BYTES = 1_700_000
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024

# Sessions are browser-scoped cookies by default: closing the browser signs you
# out. Ticking "Remember me" at sign-in marks the session permanent instead, and
# this is how long that cookie is allowed to last. It also caps the age of every
# cookie, permanent or not, because SecureCookieSessionInterface validates the
# signature against the same lifetime.
REMEMBER_SESSION_DAYS = 30
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=REMEMBER_SESSION_DAYS)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# Password hashing -----------------------------------------------------------
# Pyodide's hashlib is built without the OpenSSL key-derivation functions (no
# pbkdf2_hmac, no scrypt), so Werkzeug's password helpers cannot be used here.
#
# PBKDF2-HMAC-SHA256 is derived by, in order of preference:
#   1. hashlib.pbkdf2_hmac        - native, present on normal CPython
#   2. WebCrypto (crypto.subtle)  - native, what the Worker uses
#   3. a pure-Python fallback     - correct but ~2 ms per 1,000 iterations
# The pure-Python path is why the iteration count is low by OWASP standards: at
# 60,000 iterations it costs ~0.2 s of CPU, which on the Workers **Free** plan
# (10 ms of CPU per request) fails every sign-in with Error 1102. Native PBKDF2
# is roughly two orders of magnitude cheaper for the same iteration count.
# 100,000 iterations measured ~1.7 ms of CPU with WebCrypto, so this fits the
# Free plan's 10 ms budget with room for the rest of the request; raise
# PASSWORD_HASH_ITERATIONS (or set the Worker variable of the same name) if you
# want a stronger work factor on Workers Paid. Hashes record their own count, so
# old rows keep verifying with whatever they were created with.
PASSWORD_HASH_METHOD = "pbkdf2:sha256"
PASSWORD_HASH_ITERATIONS = 100000
PASSWORD_HASH_DIGEST = "sha256"

# Site owner accounts: signing in as one of these grants the admin panel without
# the shared ADMIN_PASSWORD. Override with the OWNER_USERNAMES Worker variable.
DEFAULT_OWNER_USERNAMES = "SystematicMIDIS"

# Profile bios, post statuses and the two feeds.
MAX_BIO_LENGTH = 500
MAX_POST_TITLE = 200

# Social links -----------------------------------------------------------------
# A profile can point at the other places a person is: a channel, a chat server,
# a personal site. They are stored as one JSON array in users.social_links
# (migration 0010) rather than a column per network, because the sites people
# use keep changing and an "other" entry has no fixed name to give a column.
#
# Each tuple is (key, label, placeholder). The label is what the editor and the
# profile chips show; the placeholder is a hint in the box, not a default - an
# empty box means "no link", which is what keeps a profile honest.
SOCIAL_PLATFORMS = (
    ("youtube", "YouTube", "youtube.com/@you"),
    ("x", "X (Twitter)", "x.com/you"),
    ("tiktok", "TikTok", "tiktok.com/@you"),
    ("instagram", "Instagram", "instagram.com/you"),
    ("discord", "Discord", "discord.gg/invite-code"),
    ("twitch", "Twitch", "twitch.tv/you"),
    ("soundcloud", "SoundCloud", "soundcloud.com/you"),
    ("bandcamp", "Bandcamp", "you.bandcamp.com"),
    ("github", "GitHub", "github.com/you"),
    ("website", "Website", "yoursite.com"),
)
SOCIAL_LABELS = {key: label for key, label, _placeholder in SOCIAL_PLATFORMS}
# Rows under "Other platforms", for everything the list above does not cover.
MAX_OTHER_SOCIAL_LINKS = 3
# The ceiling for one profile, known platforms plus the other rows. It is also
# what social_links_of() enforces when it reads the column back.
MAX_SOCIAL_LINKS = len(SOCIAL_PLATFORMS) + MAX_OTHER_SOCIAL_LINKS
MAX_SOCIAL_URL = 300
MAX_SOCIAL_LABEL = 30
POST_STATUSES = ("published", "draft")
# Every post lands in exactly one category: owner accounts write to "systematics",
# everybody else to "community". Both are public; the split just keeps the owner's
# posts separable from the community feed (and filterable on the home page).
POST_CATEGORIES = ("community", "systematics")
POST_CATEGORY_LABELS = {
    "community": "Community posts",
    "systematics": "Systematics posts",
}

# Google+ revival --------------------------------------------------------------
# The product this site is modelled on had more than one public stream: a post
# could be shared with the world, with one circle, or with nobody but its author,
# and it could live in a collection, a community or an event as well as on a
# profile. These are the limits those screens use, kept in one place so a form
# and the route that reads it cannot disagree.
POST_AUDIENCES = ("public", "circles", "private")
AUDIENCE_LABELS = {
    "public": "Public",
    "circles": "A circle",
    "private": "Only me",
}
MAX_TAGLINE_LENGTH = 100
MAX_NICKNAME_LENGTH = 40
MAX_ABOUT_LENGTH = 300
MAX_CIRCLE_NAME = 40
MAX_CIRCLE_MEMBERS = 500
MAX_COLLECTION_NAME = 40
MAX_COLLECTION_DESCRIPTION = 200
MAX_COMMUNITY_NAME = 60
MAX_COMMUNITY_DESCRIPTION = 500
MAX_EVENT_TITLE = 100
MAX_EVENT_DESCRIPTION = 2000
MAX_EVENT_LOCATION = 120
# Four images is what fits in one D1 request body inside the Free plan's CPU
# budget; each is capped at MAX_IMAGE_BYTES, so a post stays well under the 4 MB
# request backstop.
MAX_POST_IMAGES = 4
MAX_SHARE_BODY = 1000
MAX_REPORT_REASON = 500
MAX_PEOPLE_TAGGED = 10
# How many posts one page of every stream holds. Google+ loaded more as you
# scrolled; the page carries the same cursor (?before=<post id>) that the
# infinite-scroll script asks for, and the link underneath works without it.
FEED_PAGE_SIZE = 20
# Notifications pile up faster than anything else on a social site, so the page
# reads the newest slice and the rail only ever counts unread ones.
NOTIFICATION_PAGE_SIZE = 60
NOTIFICATION_KINDS = (
    "like", "comment", "reply", "mention", "follow", "share",
    "comment_like", "tag",
)
NOTIFICATION_LABELS = {
    "like": "Somebody +1s my posts",
    "comment": "Somebody comments on my posts",
    "reply": "Somebody replies to my comments",
    "mention": "Somebody @mentions me",
    "follow": "Somebody follows me",
    "share": "Somebody reshares my posts",
    "comment_like": "Somebody +1s my comments",
    "tag": "Somebody tags me in a post",
}
# The rest of the G+ surfaces, added by migration 0017.
MAX_PAGE_NAME = 60
MAX_PAGE_TAGLINE = 120
MAX_PAGE_ABOUT = 2000
MAX_ALBUM_NAME = 40
MAX_ALBUM_DESCRIPTION = 200
MAX_SPARK_NAME = 50
MAX_SPARK_DESCRIPTION = 400
MAX_SPARK_NOTE = 200
MAX_HANGOUT_TITLE = 100
MAX_EMAIL = 120
# Emails are queued and flushed in batches so a Worker request never waits on a
# mail provider.
EMAIL_BATCH_SIZE = 20
DEFAULT_EMAIL_API_URL = "https://api.resend.com/emails"


# Followers ------------------------------------------------------------------
# One row per relationship in ``follows``; the profile pages list them newest first.
# The cap keeps a runaway account from turning a profile into an unbounded query.
FOLLOW_LIST_LIMIT = 200
# The profile header previews this many followers and followings before "View all".
FOLLOW_PREVIEW_LIMIT = 6

# Link cards ----------------------------------------------------------------
# A post that contains a web link gets a card underneath it, built from the
# target page's Open Graph tags - the same tags Discord, Slack and every other
# chat client read. The card is fetched once, when the post is saved, and cached
# in the D1 `link_previews` table, so rendering a feed never waits on a
# third-party server (see migrations/0007_link_previews.sql).
LINK_PREVIEW_USER_AGENT = (
    "Mozilla/5.0 (compatible; SystematicsLinkPreview/1.0; +link-preview-bot)"
)
LINK_PREVIEW_TIMEOUT_SECONDS = 8
# How much of a page we look at. Open Graph tags have to live in the document
# <head>, so reading far past this only burns CPU scanning markup that cannot
# contain a card (measured on the deployed Worker: a post save is ~130-270 ms
# CPU with or without a link card, so the scan is not what costs.)
LINK_PREVIEW_MAX_CHARS = 150_000
LINK_PREVIEW_TITLE_LIMIT = 200
LINK_PREVIEW_DESCRIPTION_LIMIT = 300
# A card that worked is refreshed after a week; a link that produced nothing is
# retried after an hour, so a page that was briefly down still gets its card.
LINK_PREVIEW_TTL_SECONDS = 7 * 24 * 60 * 60
LINK_PREVIEW_RETRY_SECONDS = 60 * 60
# Each refresh costs one outbound request, and the Free plan allows 50
# subrequests per invocation, so a bulk refresh stops well short of that.
MAX_LINK_REFRESH_PER_RUN = 20
# The update log ------------------------------------------------------------
# A post can write [COMMITS] and it becomes the repository's commit history, one
# line per commit - an update log that fills itself in without anybody editing
# the post. The list is cached in D1 (migration 0011) and re-read at most once
# per COMMIT_LOG_TTL_SECONDS, because GitHub's unauthenticated API allows 60
# requests an hour per IP and a Worker's egress addresses are shared with every
# other Worker on the network.
COMMIT_LOG_REPO = "systematicmidis/systematics-website"
COMMIT_LOG_LIMIT = 10
# What the feed shows: the whole list belongs on the post, not in a card.
COMMIT_LOG_EXCERPT_LIMIT = 1
COMMIT_LOG_TTL_SECONDS = 5 * 60
# A failed attempt is remembered for longer than a good one, so a rate-limited
# Worker does not turn every page render into another refused request.
COMMIT_LOG_RETRY_SECONDS = 15 * 60
COMMIT_LOG_TIMEOUT_SECONDS = 5
COMMIT_LOG_MESSAGE_LIMIT = 120
# What a commit id looks like. Both the GitHub response and the cached row are
# held to this, so a row written into the cache by anything else cannot reach
# the page - and the cache has no address in it to be trusted in the first
# place, since a commit's page is derived from the id when the post renders.
COMMIT_SHA_RE = re.compile(r"[0-9a-fA-F]{7,40}")

# Direct file links are skipped: there is no page to read a card from, and some
# of them are large downloads we would be pulling for nothing.
LINK_PREVIEW_SKIP_EXTENSIONS = (
    ".zip", ".7z", ".rar", ".tar", ".gz", ".mid", ".midi", ".mp3", ".mp4",
    ".wav", ".ogg", ".webm", ".mov", ".avi", ".exe", ".msi", ".dmg", ".iso",
    ".apk", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".csv", ".json", ".xml", ".txt", ".css",
    ".js", ".woff", ".woff2", ".ttf",
)

try:  # present on regular CPython, missing in the Pyodide runtime
    from hashlib import pbkdf2_hmac as _native_pbkdf2_hmac
except ImportError:  # pragma: no cover - depends on the runtime
    _native_pbkdf2_hmac = None


def _pbkdf2_hmac_py(password, salt, iterations, dklen):
    """Minimal PBKDF2-HMAC-SHA256 for runtimes without hashlib.pbkdf2_hmac."""
    digest_size = hashlib.sha256().digest_size
    blocks = -(-dklen // digest_size)
    derived = b""
    for index in range(1, blocks + 1):
        u = hmac.new(password, salt + struct.pack(">I", index), "sha256").digest()
        accumulator = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac.new(password, u, "sha256").digest()
            accumulator ^= int.from_bytes(u, "big")
        derived += accumulator.to_bytes(digest_size, "big")
    return derived[:dklen]


def _pbkdf2_hmac_webcrypto(password, salt, iterations, dklen):
    """PBKDF2-HMAC-SHA256 via the runtime's native WebCrypto implementation."""
    subtle = webcrypto_subtle()
    key = run_sync(
        subtle.importKey(
            "raw", to_js(password), to_js({"name": "PBKDF2"}), False, to_js(["deriveBits"])
        )
    )
    bits = run_sync(
        subtle.deriveBits(
            to_js({
                "name": "PBKDF2",
                "salt": to_js(salt),
                "iterations": iterations,
                "hash": "SHA-256",
            }),
            key,
            dklen * 8,
        )
    )
    return to_bytes(bits)


def password_iterations():
    """Iteration count for new hashes: Worker variable if set, else the default."""
    configured = None
    try:
        configured = getattr(env(), "PASSWORD_HASH_ITERATIONS", None)
    except Exception:  # no request context (for example at import time)
        pass
    configured = configured or os.environ.get("PASSWORD_HASH_ITERATIONS")
    try:
        return int(configured)
    except (TypeError, ValueError):
        return PASSWORD_HASH_ITERATIONS


def _derive(password, salt, iterations):
    """Return the hex PBKDF2-HMAC-SHA256 digest of password and salt."""
    dklen = hashlib.sha256().digest_size
    if _native_pbkdf2_hmac is not None:
        return _native_pbkdf2_hmac(PASSWORD_HASH_DIGEST, password, salt, iterations).hex()
    try:
        return _pbkdf2_hmac_webcrypto(password, salt, iterations, dklen).hex()
    except Exception as exc:  # pragma: no cover - only if WebCrypto is unavailable
        app.logger.warning("WebCrypto PBKDF2 unavailable, using pure Python: %s", exc)
    return _pbkdf2_hmac_py(password, salt, iterations, dklen).hex()


def hash_password(password):
    """Hash a password as ``pbkdf2:sha256:<iterations>$<salt>$<hash>``."""
    salt = secrets.token_hex(8)
    iterations = password_iterations()
    return (
        f"{PASSWORD_HASH_METHOD}:{iterations}"
        f"${salt}${_derive(password.encode(), salt.encode(), iterations)}"
    )


def verify_password(stored, password):
    """Check a password against a stored hash, including Werkzeug hashes."""
    if not stored or not password:
        return False
    if stored.startswith(f"{PASSWORD_HASH_METHOD}:"):
        try:
            method, salt, expected = stored.split("$", 2)
            iterations = int(method.rsplit(":", 1)[1])
        except ValueError:
            return False
        return hmac.compare_digest(
            _derive(password.encode(), salt.encode(), iterations), expected
        )
    # Hashes written elsewhere (for example by app.py); these need OpenSSL.
    try:
        return check_password_hash(stored, password)
    except Exception:
        return False


class CloudflareSessionInterface(SecureCookieSessionInterface):
    """Use a Cloudflare Worker secret instead of a filesystem/environment secret."""
    def get_signing_serializer(self, app):
        env = request.environ.get("workers.env")
        secret = getattr(env, "SESSION_SECRET", None) if env is not None else None
        if not secret:
            secret = os.environ.get("SESSION_SECRET") or "CHANGE-ME-SESSION-SECRET"
        if not secret:
            return None
        from itsdangerous import URLSafeTimedSerializer
        signer_kwargs = dict(
            key_derivation=self.key_derivation,
            digest_method=self.digest_method,
        )
        return URLSafeTimedSerializer(
            secret,
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs=signer_kwargs,
        )


app.session_interface = CloudflareSessionInterface()


def env():
    return request.environ["workers.env"]


def py(value):
    try:
        return value.to_py()
    except Exception:
        return value


def to_bytes(value):
    """Copy a JavaScript ArrayBuffer/typed array into Python bytes."""
    if value is None:
        return b""
    converter = getattr(value, "to_py", None)
    if converter is not None:
        value = converter()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return bytes(memoryview(value))


def blob_to_bytes(value):
    """Normalise a BLOB returned by D1 into Python bytes.

    Depending on the runtime the column arrives as bytes, a memoryview or an
    untranslated JavaScript ArrayBuffer, so try each shape.
    """
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        return bytes(value)
    try:
        return to_bytes(value)
    except Exception:
        return bytes(value.to_bytes()) if hasattr(value, "to_bytes") else b""


def read_body_bytes(source):
    """Read the whole body of a JS Response.

    Responses expose different readers depending on where they come from
    (bytes() for Workers responses, arrayBuffer() elsewhere), so try each.
    """
    for reader_name in ("bytes", "arrayBuffer"):
        reader = getattr(source, reader_name, None)
        if reader is not None:
            return to_bytes(run_sync(reader()))
    body = getattr(source, "body", None)
    if body is not None:
        return to_bytes(run_sync(body.arrayBuffer()))
    return b""


def db():
    return env().DB


def query(sql, *params):
    stmt = db().prepare(sql)
    if params:
        stmt = stmt.bind(*params)
    result = run_sync(stmt.run())
    result = py(result)
    rows = result.get("results", []) if isinstance(result, dict) else []
    return rows


def first(sql, *params):
    stmt = db().prepare(sql)
    if params:
        stmt = stmt.bind(*params)
    result = run_sync(stmt.first())
    if result is None:
        return None
    return py(result)


def execute(sql, *params):
    stmt = db().prepare(sql)
    if params:
        stmt = stmt.bind(*params)
    return py(run_sync(stmt.run()))


def admin_password():
    value = getattr(env(), "ADMIN_PASSWORD", None)
    return value or os.environ.get("ADMIN_PASSWORD", "change-me")


# Accounts listed here (comma separated) get the admin panel just by signing in,
# without the shared admin password. Override with the OWNER_USERNAMES Worker
# variable to add or change owners without touching this file.
def owner_usernames():
    value = getattr(env(), "OWNER_USERNAMES", None) or os.environ.get("OWNER_USERNAMES")
    return {
        name.strip().lower()
        for name in (value or DEFAULT_OWNER_USERNAMES).split(",")
        if name.strip()
    }


def current_user():
    """The signed-in user row; looked up at most once per request."""
    if "current_user" not in g:
        uid = session.get("user_db_id")
        g.current_user = first("SELECT * FROM users WHERE id=?", uid) if uid else None
    return g.current_user


def is_owner_username(username):
    """True when this account is listed in OWNER_USERNAMES."""
    return (username or "").lower() in owner_usernames()


def is_admin():
    """True for the shared admin password and for site owner accounts."""
    if "is_admin" not in g:
        user = current_user()
        username = (user["username"] or "").lower() if user else ""
        g.is_admin = bool(session.get("admin")) or username in owner_usernames()
    return g.is_admin


def is_owner():
    """True only for an account listed in OWNER_USERNAMES.

    Stricter than :func:`is_admin`, which the shared ADMIN_PASSWORD also opens:
    the owner panel on the settings page, and everything it can do, is for the
    account(s) named in OWNER_USERNAMES and nobody else. The list comes from the
    Worker variable of the same name (wrangler.jsonc), so adding a second owner
    account is a config change rather than a code change.
    """
    if "is_owner" not in g:
        user = current_user()
        g.is_owner = bool(user and is_owner_username(user["username"]))
    return g.is_owner


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "is_admin": is_admin(),
        "is_owner": is_owner(),
        # Every template can warn the signed-in visitor of their own restrictions
        # (base.html shows them), which is why this is computed here and not in
        # one route.
        "my_bans": active_bans(current_user()) if session.get("user_db_id") else {},
        # The rail carries an unread count, so this is asked on every page too.
        "unread_messages": (
            unread_messages(current_user()) if session.get("user_db_id") else 0
        ),
        # The bell beside Messages, same reasoning.
        "unread_notifications": (
            unread_notifications(current_user())
            if session.get("user_db_id") else 0
        ),
        # Templates that carry revival-only screens ask this instead of assuming
        # migration 0016 has been applied.
        "gplus": gplus_schema(),
    }


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_db_id"):
            flash("You need to be logged in to do that.", "error")
            return redirect(url_for("login", next=request.path))
        # The cookie is checked against the database, not just for its presence.
        # A session can outlive the row it names - a database restored from a
        # backup, a local one reset, a row removed by hand in D1 - and every
        # signed-in page indexes the account's own row, so a stale session used
        # to raise its way through the page. In front of a Cloudflare Worker
        # that is an error 1101 for whoever is reading, so the cookie is dropped
        # and the visitor is asked to sign in instead.
        if not current_user():
            session.clear()
            flash("That account no longer exists. Sign in, or create a new one.", "error")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash("Sign in as a site owner to manage the site.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def owner_required(f):
    """Gate for the owner-only half of the settings page.

    A signed-in account that is not an owner gets sent back to their own
    settings; a signed-out visitor is asked to sign in first. The template
    hides this section, but the check lives here too - hiding markup is not
    access control, and these routes are reachable by hand.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_owner():
            flash("That part of settings is for the site owner.", "error")
            if session.get("user_db_id"):
                return redirect(url_for("settings"))
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


# Account deletion and moderation bans ---------------------------------------
# Two moderation tools, described together because they share the same row.
#
# Deleting is a *soft* delete: the row survives so the posts and comments the
# person wrote keep an author and old threads do not collapse into one-sided
# conversations (the foreign keys cascade, so a hard DELETE would take them all
# with it). What goes is everything that identifies the person - the display name
# becomes DELETED_ACCOUNT_NAME, the handle is released as deleted_user_<id>, and
# the password hash, bio, avatar and banner are cleared - and their profile stops
# resolving, so the account can never be signed into again.
DELETED_ACCOUNT_NAME = "[ Account Deleted ]"

# What an admin can hand out. Each choice covers exactly one thing - signing in at
# all (account), commenting, or posting - and is either temporary (an expiry
# picked from BAN_DURATIONS) or permanent.
BAN_CHOICES = {
    "comment_temp": ("comment", False, "Temporary comment ban"),
    "comment_perm": ("comment", True, "Comment ban"),
    "post_temp": ("post", False, "Temporary post ban"),
    "post_perm": ("post", True, "Post ban"),
    "account_temp": ("account", False, "Temporary account ban"),
    "account_perm": ("account", True, "Permanent account ban"),
}
BAN_KINDS = ("account", "comment", "post")
BAN_DURATIONS = {
    "1h": ("1 hour", timedelta(hours=1)),
    "1d": ("1 day", timedelta(days=1)),
    "3d": ("3 days", timedelta(days=3)),
    "1w": ("1 week", timedelta(days=7)),
    "30d": ("30 days", timedelta(days=30)),
}
DEFAULT_BAN_DURATION = "1w"
BAN_REASON_MAX = 200
DB_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def utcnow():
    """Naive UTC now, matching the way D1's CURRENT_TIMESTAMP is stored."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def db_time(value):
    """Parse a stored timestamp, or None when it is missing or malformed."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value), DB_TIME_FORMAT)
    except (TypeError, ValueError):
        return None


def ban_columns(kind):
    """The expiry and permanent-flag columns for one ban kind.

    Column names are built from the BAN_KINDS whitelist, never from a request, so
    the f-strings that use this cannot be pointed at something else.
    """
    if kind not in BAN_KINDS:
        raise ValueError(f"unknown ban kind: {kind}")
    return f"{kind}_ban_until", f"{kind}_ban_permanent"


def ban_state(user):
    """Every ban on ``user``: {kind: {"active", "permanent", "until"}}.

    Expiry is judged here instead of by a cleanup job, so a temporary ban lifts
    itself the moment its expiry passes and leaves nothing behind.
    """
    state = {}
    for kind in BAN_KINDS:
        until_column, permanent_column = ban_columns(kind)
        permanent = bool(user.get(permanent_column)) if user else False
        until = user.get(until_column) if user else None
        expires_at = db_time(until)
        active = permanent or bool(expires_at and expires_at > utcnow())
        state[kind] = {
            "active": active,
            "permanent": permanent,
            # An expiry in the past is not worth showing anyone.
            "until": None if permanent else (until if active else None),
        }
    return state


def active_bans(user):
    """Only the bans that still bite, for notices and badges."""
    if not user:
        return {}
    return {kind: info for kind, info in ban_state(user).items() if info["active"]}


BAN_MESSAGES = {
    "account": (
        "Your account is permanently banned from this site.",
        "Your account is banned until {until} UTC.",
    ),
    "comment": (
        "You are permanently banned from commenting.",
        "You are banned from commenting until {until} UTC.",
    ),
    "post": (
        "You are permanently banned from posting.",
        "You are banned from posting until {until} UTC.",
    ),
}


def ban_message(kind, info):
    """The sentence a banned person sees, written from their own point of view."""
    permanent, temporary = BAN_MESSAGES[kind]
    if info.get("permanent") or not info.get("until"):
        return permanent
    return temporary.format(until=info["until"])


def is_banned(user, kind):
    """True when ``user`` cannot do the thing ``kind`` names right now."""
    return bool(user) and ban_state(user)[kind]["active"]


def posting_blocked():
    """Flash a post ban and report whether writing a post is refused."""
    info = active_bans(current_user()).get("post")
    if info:
        flash(ban_message("post", info), "error")
        return True
    return False


def name_initial(value):
    """One character for an avatar: a letter, or a cross for a deleted account."""
    text = (value or "").strip()
    if not text:
        return "?"
    if text == DELETED_ACCOUNT_NAME:
        return "✕"
    return text[:1].upper()


def anonymise_account(user):
    """Delete ``user``'s account without deleting what they wrote.

    Runs without the session cleared, so the caller decides where to send the
    visitor afterwards; the cached user is dropped because the row just changed
    under it.
    """
    for column in ("profile_picture", "banner"):
        delete_upload(user.get(column))
    # social_links goes with the bio and the images: a tombstone has no person
    # left to point at, and leaving their channels on it would outlive the
    # account they chose to close.
    execute(
        """UPDATE users SET username=?, display_name=?, password_hash='', bio=NULL,
                           profile_picture=NULL, banner=NULL, social_links=NULL,
                           deleted_at=datetime('now')
           WHERE id=?""",
        f"deleted_user_{user['id']}", DELETED_ACCOUNT_NAME, user["id"],
    )
    # Follower rows in either direction go, so a deleted account disappears from
    # every list instead of sitting there behind a handle nobody can open.
    execute("DELETE FROM follows WHERE follower_id=? OR followed_id=?", user["id"], user["id"])
    # Conversations survive, deliberately: a thread belongs to both people in it,
    # so deleting one account must not quietly delete what its owner was told (or
    # erase the other person's half of a conversation). The tombstone cannot sign
    # in, so nothing is left readable to the person who left - it reads as
    # "[ Account Deleted ]" to whoever they were talking to. The moderation log
    # stays for the same reason.
    g.pop("current_user", None)


def moderation_block(target):
    """Why ``target`` cannot be banned, or None when it can.

    Owner accounts are protected: owner rights come from OWNER_USERNAMES, so
    banning one would not remove those rights, it would only lock the owner out
    of their own admin panel.
    """
    if not target:
        return "That account no longer exists."
    if target.get("deleted_at"):
        return "That account has been deleted."
    if is_owner_username(target.get("username")):
        return "Owner accounts cannot be banned."
    me = current_user()
    if me and me["id"] == target["id"]:
        return "You cannot ban your own account."
    return None


@app.before_request
def enforce_moderation():
    """Sign out deleted or account-banned sessions before any route can use them.

    Static assets are skipped so a restricted visitor still gets a styled page.
    """
    if request.path.startswith(("/static/", "/uploads/")):
        return None
    user = current_user()
    if not user:
        return None
    if user.get("deleted_at"):
        session.clear()
        flash("That account has been deleted.", "error")
        return redirect(url_for("home"))
    info = active_bans(user).get("account")
    if info:
        # Clearing the session is the ban: the signed-in cookie stops being
        # accepted, and the flash is written after it so the person is told why.
        session.clear()
        # The inbox needs a session, so the banned person has nowhere to read the
        # notice about this ban. The account id goes into the session that was just
        # emptied (still signed, so it cannot be forged) and the sign-in page shows
        # that account's own notice - see login().
        session["notice_for"] = user["id"]
        flash(ban_message("account", info), "error")
        return redirect(url_for("login"))
    return None


# Messages and the moderation log --------------------------------------------
# The site speaks to one person at a time in that person's inbox. Two writers
# use it: the site's own bot, which reports what happened to an account, and an
# admin, who can write to anybody by hand. Both go through send_message(), so
# there is one place that trims, stores and - when migration 0014 has not been
# applied yet - fails quietly rather than breaking the page.
#
# Every notice and every admin action is also written to `moderation_log`, which
# is what lets the admin panel answer "what did this person get banned for?" long
# after the last ban: migration 0009's columns on `users` only remember the last
# one. The log keeps the post or comment that caused it as a *snapshot*, so the
# answer survives that comment being deleted.
# Messages are Hangouts-shaped: a conversation is a thread between two accounts
# and every message belongs to one. A `conversations` row is the thread (migration
# 0015), one per pair, and the message itself is a row in `messages` - the table
# migration 0014 introduced, which is why a ban notice is simply a message from
# the moderation account rather than a page of its own.
#
# Two writers use it: people writing to each other, and the site. The site's
# messages come from the SystematicsModeration account, so a notice looks like a
# message from a person - it can be replied to, and the reply lands in that
# account's inbox, which the admin panel reads on its behalf. When that account
# does not exist (a fresh local database, or somebody renamed it) notices are
# still written; they simply have no thread to live in and the inbox lists them
# on their own.
MODERATION_USERNAME_DEFAULT = "SystematicsModeration"
# The name a notice falls back to when there is no moderation account to send it.
MODERATION_LABEL_FALLBACK = "Systematics Moderation"
MAX_MESSAGE_SUBJECT = 120
# A notice is longer than a chat message: it quotes what it is about.
MAX_MESSAGE_BODY = 4000
# A direct message is held to the same ceiling as a comment, so nobody can paste a
# novel into somebody's inbox.
MAX_DM_LENGTH = 2000
# How many messages of a thread to render, and how many threads the inbox lists.
CONVERSATION_PAGE_MESSAGES = 200
CONVERSATION_PAGE_THREADS = 60
# How much of a body the thread list shows before the name and time take over.
MESSAGE_PREVIEW_LENGTH = 160
# How much of a moderated post or comment is quoted back inside a notice.
MODERATION_EXCERPT_LENGTH = 300
# What a row's `kind` names: a ban, a lifted ban, an admin's own words, or a
# notice the site wrote for some other reason.
MESSAGE_KINDS = ("ban", "unban", "message", "notice")
# How many of an account's own posts and comments the admin's cause picker offers.
MODERATION_PICKER_PER_USER = 12


def actor_name(user):
    """How the person behind an admin action is named in notices and the log."""
    return (user or {}).get("username") or "admin"


def moderation_username():
    """Which account the site writes as. Override with MODERATION_USERNAME."""
    value = None
    try:
        value = getattr(env(), "MODERATION_USERNAME", None)
    except Exception:  # no request context (for example at import time)
        value = None
    return ((value or os.environ.get("MODERATION_USERNAME")
             or MODERATION_USERNAME_DEFAULT).strip())


def moderation_account():
    """The account automatic notices come from, or None when it does not exist.

    One lookup per request, cached on ``g``, because the inbox, a thread and the
    admin panel all ask for it and each page should pay for it once.
    """
    if "moderation_account" not in g:
        try:
            g.moderation_account = first(
                "SELECT * FROM users WHERE username=? COLLATE NOCASE",
                moderation_username(),
            )
        except Exception as exc:
            app.logger.warning("Could not look up the moderation account: %s", exc)
            g.moderation_account = None
    return g.moderation_account


def is_moderation_account(user):
    """True for the account the site writes as - which can never be an admin."""
    return bool(user) and (user.get("username") or "").lower() == moderation_username().lower()


BAN_SUBJECTS = {
    "account": "Your account has been banned",
    "comment": "You have been banned from commenting",
    "post": "You have been banned from posting",
}
# What each ban is *about*, for the sentence that names it.
BAN_AREAS = {"account": "signing in", "comment": "commenting", "post": "posting"}
# What a ban leaves open. These sit beside BAN_MESSAGES on purpose: the sentence
# a visitor reads in the banner and the one in their inbox must not disagree.
BAN_SCOPE_NOTES = {
    "account": "While it lasts you cannot sign in, and any browser you were signed "
               "in on has been signed out.",
    "comment": "You can still sign in, read everything, write posts and follow "
               "people - only commenting is closed to you.",
    "post": "You can still sign in, read everything, comment and follow people - "
            "only writing posts is closed to you.",
}
UNBAN_NOTES = {
    "account": "you can sign in again",
    "comment": "you can comment again",
    "post": "you can write posts again",
}


def message_preview(body):
    """The first line of a body, short enough for the inbox list.

    A message written with a ``[label](address)`` link reads as its label here.
    The list is a glance at who said what, and the brackets plus a long address
    would crowd out the words - the link itself is a link in the conversation
    beside it, which is where anybody clicks it.
    """
    flat = LINK_IN_TEXT_RE.sub(
        lambda match: match.group(1) if match.group(1) is not None else match.group(0),
        body or "",
    )
    return clean_text(flat, MESSAGE_PREVIEW_LENGTH)


def moderatable_content(users, per_user=MODERATION_PICKER_PER_USER):
    """Each account's newest posts and comments, for the admin's cause picker.

    Two queries for the whole page rather than one per account, and the newest
    few per person: the picker exists to name the thing that was just reported,
    not to be an archive browser. Labels are built here so the template only has
    to print them.
    """
    by_user = {person["id"]: [] for person in users}
    rows = query("SELECT id, user_id, title, created_at FROM posts "
                 "WHERE user_id IS NOT NULL ORDER BY id DESC")
    for row in rows:
        items = by_user.setdefault(row["user_id"], [])
        if len(items) < per_user:
            items.append({
                "value": f"post:{row['id']}",
                "kind": "post",
                "label": f"Post \u00b7 {row['title']} \u00b7 {(row['created_at'] or '')[:16]}",
            })
    rows = query("""SELECT comments.id, comments.user_id, comments.content,
                          comments.created_at, posts.title AS post_title
                   FROM comments JOIN posts ON posts.id = comments.post_id
                   ORDER BY comments.id DESC""")
    for row in rows:
        items = by_user.setdefault(row["user_id"], [])
        if len(items) < per_user:
            items.append({
                "value": f"comment:{row['id']}",
                "kind": "comment",
                "label": f"Comment on {row['post_title']} \u00b7 "
                         f"{clean_text(row['content'], 60)} \u00b7 "
                         f"{(row['created_at'] or '')[:16]}",
            })
    return by_user


def moderation_excerpt(value):
    """One line of somebody's own writing, as quoted back to them in a notice."""
    return clean_text(value, MODERATION_EXCERPT_LENGTH)


def unread_messages(user):
    """How many of ``user``'s messages are still unread.

    Asked on every page for the rail badge, so a database that has not had
    migration 0014 applied reports none instead of failing the render - the same
    defensive reading the admin panel does for migration 0009's columns.
    """
    if not user:
        return 0
    try:
        row = first(
            "SELECT COUNT(*) AS unread FROM messages "
            "WHERE recipient_id=? AND read_at IS NULL",
            user["id"],
        )
    except Exception as exc:
        app.logger.warning("Could not count unread messages: %s", exc)
        return 0
    return int(row["unread"]) if row else 0


def send_message(recipient_id, subject, body, *, sender=None, kind="notice",
                 about=None, ban=None, conversation_id=None):
    """Put one message in somebody's inbox; returns its id, or None on failure.

    ``sender`` is the account the message appears to come from. A notice passes
    nothing and gets the moderation account, so it reads as a message from a
    person rather than from nowhere - and when that account does not exist the
    label falls back to MODERATION_LABEL_FALLBACK with no sender id, which is the
    shape the inbox shows on its own. ``about``/``ban`` carry the moderation
    context that makes a notice still readable months later.

    A failure is logged and swallowed: a notice is never worth losing the admin
    action that produced it, and the ban itself has already been saved.
    """
    about = about or {}
    ban = ban or {}
    if sender is None:
        sender = moderation_account() or {}
    try:
        execute(
            """INSERT INTO messages
                 (recipient_id, sender_id, sender_label, kind, subject, body,
                  about_kind, about_id, about_title, about_excerpt, about_url,
                  ban_kind, ban_permanent, ban_until, conversation_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            recipient_id,
            sender.get("id"),
            sender.get("display_name") or sender.get("username")
            or MODERATION_LABEL_FALLBACK,
            kind if kind in MESSAGE_KINDS else "notice",
            (subject or "")[:MAX_MESSAGE_SUBJECT],
            (body or "")[:MAX_MESSAGE_BODY],
            about.get("kind"), about.get("id"), about.get("title"),
            about.get("excerpt"), about.get("url"),
            ban.get("kind"), 1 if ban.get("permanent") else 0, ban.get("until"),
            conversation_id,
        )
    except Exception as exc:
        app.logger.warning("Could not send a message to %s: %s", recipient_id, exc)
        return None
    created = first("SELECT last_insert_rowid() AS id")
    if conversation_id:
        touch_conversation(conversation_id)
    return created["id"] if created else None


# Conversations ---------------------------------------------------------------
# One thread per pair of accounts. The pair is always stored small-id-first so
# the same two people cannot end up with two threads, which is also why every
# lookup goes through conversation_pair() instead of comparing ids by hand.


def conversation_pair(first_id, second_id):
    """The two account ids in the order a `conversations` row stores them."""
    return (first_id, second_id) if first_id <= second_id else (second_id, first_id)


def touch_conversation(conversation_id):
    """Stamp a thread as just used, which is what the inbox orders by."""
    try:
        execute("UPDATE conversations SET last_message_at=datetime('now') WHERE id=?",
                conversation_id)
    except Exception as exc:
        app.logger.warning("Could not touch conversation %s: %s", conversation_id, exc)


def conversation_by_id(conversation_id):
    """One thread, or None - including when migration 0015 is not applied yet."""
    try:
        return first("SELECT * FROM conversations WHERE id=?", conversation_id)
    except Exception as exc:
        app.logger.warning("Could not read conversation %s: %s", conversation_id, exc)
        return None


def conversation_between(first_id, second_id):
    """The thread between two accounts if it exists, else None. Never creates."""
    low, high = conversation_pair(first_id, second_id)
    try:
        return first("SELECT * FROM conversations WHERE user_low=? AND user_high=?",
                     low, high)
    except Exception as exc:  # migration 0015 not applied yet
        app.logger.warning("Could not read a conversation: %s", exc)
        return None


def open_conversation(first_id, second_id):
    """The thread between two accounts, created on first use.

    Returns None when the tables are not there yet, which is what keeps a ban
    working (and merely unthreaded) on a database without migration 0015.
    """
    low, high = conversation_pair(first_id, second_id)
    existing = conversation_between(first_id, second_id)
    if existing:
        return existing
    try:
        execute("INSERT OR IGNORE INTO conversations (user_low, user_high, created_at) "
                "VALUES (?, ?, datetime('now'))", low, high)
    except Exception as exc:
        app.logger.warning("Could not open a conversation: %s", exc)
        return None
    return conversation_between(first_id, second_id)


def conversation_is_participant(conversation, user):
    """True when ``user`` is one of the two people in this thread."""
    if not conversation or not user:
        return False
    return user["id"] in (conversation["user_low"], conversation["user_high"])


def conversation_participant_ids(conversation):
    """The two account ids in a thread."""
    if not conversation:
        return ()
    return (conversation["user_low"], conversation["user_high"])


def conversation_other_id(conversation, user_id):
    """The account on the other side of the thread from ``user_id``."""
    low, high = conversation_participant_ids(conversation)
    return high if user_id == low else low


def user_by_id(user_id):
    """One account row, or None."""
    if not user_id:
        return None
    try:
        return first("SELECT * FROM users WHERE id=?", user_id)
    except Exception as exc:
        app.logger.warning("Could not read account %s: %s", user_id, exc)
        return None


def conversation_with_moderation(conversation):
    """True when the site's own account is one end of this thread.

    That is the test for "an admin may stand in for it": the moderation account
    cannot sign in and answer for itself, so the panel reads and writes its side.
    """
    account = moderation_account()
    return bool(account) and account["id"] in conversation_participant_ids(conversation)


def may_view_conversation(conversation, user):
    """Who may open a thread: the two people in it, plus an admin for the site's."""
    if conversation_is_participant(conversation, user):
        return True
    return bool(is_admin() and conversation_with_moderation(conversation))


def conversation_messages(conversation_id, limit=CONVERSATION_PAGE_MESSAGES):
    """A thread's messages, oldest first, each carrying its sender's account."""
    try:
        return query(
            """SELECT messages.*,
                      users.username AS sender_username,
                      users.display_name AS sender_display_name,
                      users.profile_picture AS sender_picture,
                      users.user_id AS sender_public_id,
                      users.deleted_at AS sender_deleted
                 FROM messages LEFT JOIN users ON users.id = messages.sender_id
                WHERE messages.conversation_id=?
                ORDER BY messages.id LIMIT ?""",
            conversation_id, limit,
        )
    except Exception as exc:
        app.logger.warning("Could not read conversation %s: %s", conversation_id, exc)
        return []


def thread_ban_states(thread, rows):
    """For each notice in a thread, whether the ban it records is still in force.

    Asked of the account the notice was addressed to, at read time, so a notice
    inside a thread cannot keep claiming somebody is banned after that ban ran out
    or was lifted - the same rule the single-notice page follows. Threads with no
    notices in them (which is most of them) cost nothing: the loop never runs.
    """
    states = {}
    if not thread or not any((row or {}).get("ban_kind") for row in rows or []):
        return states
    people = {}
    for user_id in conversation_participant_ids(thread):
        person = user_by_id(user_id)
        if person:
            people[person["id"]] = person
    for row in rows:
        if row.get("ban_kind"):
            states[row["id"]] = is_banned(people.get(row.get("recipient_id")),
                                          row["ban_kind"])
    return states


def conversations_for(user, limit=CONVERSATION_PAGE_THREADS):
    """Every thread ``user`` is in, newest first, with who and what was said last.

    Two joins rather than a CASE, so the *other* participant can be picked in
    Python where it is obvious which one is not the reader. One query for the
    whole inbox: the last body, its sender and the unread count come from
    correlated subqueries rather than a query per thread.
    """
    try:
        rows = query(
            """SELECT conversations.*,
                      low_user.id AS low_id, low_user.username AS low_username,
                      low_user.display_name AS low_display_name,
                      low_user.profile_picture AS low_picture,
                      low_user.user_id AS low_public_id,
                      low_user.deleted_at AS low_deleted,
                      high_user.id AS high_id, high_user.username AS high_username,
                      high_user.display_name AS high_display_name,
                      high_user.profile_picture AS high_picture,
                      high_user.user_id AS high_public_id,
                      high_user.deleted_at AS high_deleted,
                      (SELECT body FROM messages WHERE conversation_id=conversations.id
                        ORDER BY id DESC LIMIT 1) AS last_body,
                      (SELECT sender_id FROM messages WHERE conversation_id=conversations.id
                        ORDER BY id DESC LIMIT 1) AS last_sender_id,
                      (SELECT created_at FROM messages WHERE conversation_id=conversations.id
                        ORDER BY id DESC LIMIT 1) AS last_at,
                      (SELECT COUNT(*) FROM messages
                        WHERE conversation_id=conversations.id AND recipient_id=?
                          AND read_at IS NULL) AS unread,
                      (SELECT COUNT(*) FROM messages
                        WHERE conversation_id=conversations.id) AS total
                 FROM conversations
                 JOIN users low_user ON low_user.id = conversations.user_low
                 JOIN users high_user ON high_user.id = conversations.user_high
                WHERE conversations.user_low=? OR conversations.user_high=?
                ORDER BY COALESCE(conversations.last_message_at, conversations.created_at) DESC,
                         conversations.id DESC
                LIMIT ?""",
            user["id"], user["id"], user["id"], limit,
        )
    except Exception as exc:  # migration 0015 not applied yet
        app.logger.warning("Could not read conversations: %s", exc)
        return []
    threads = []
    for row in rows:
        mine_low = row["low_id"] == user["id"]
        threads.append({
            "conversation": row,
            "other": {
                "id": row["high_id"] if mine_low else row["low_id"],
                "username": row["high_username"] if mine_low else row["low_username"],
                "display_name": row["high_display_name"] if mine_low else row["low_display_name"],
                "profile_picture": row["high_picture"] if mine_low else row["low_picture"],
                "user_id": row["high_public_id"] if mine_low else row["low_public_id"],
                "deleted_at": row["high_deleted"] if mine_low else row["low_deleted"],
            },
            "last_body": row["last_body"],
            "last_at": row["last_at"],
            "last_is_mine": row["last_sender_id"] == user["id"],
            "unread": int(row["unread"] or 0),
            "total": int(row["total"] or 0),
        })
    return threads


def mark_conversation_read(conversation, reader_ids):
    """Mark messages addressed to ``reader_ids`` as read, in this thread only.

    Opening a thread is what marks it read, so there is no separate step to
    forget, and messages the reader sent are left alone - whether the other
    person has seen them is theirs to say.
    """
    readers = [reader_id for reader_id in set(reader_ids) if reader_id]
    if not conversation or not readers:
        return
    try:
        execute(
            "UPDATE messages SET read_at=datetime('now') "
            "WHERE conversation_id=? AND read_at IS NULL AND recipient_id IN "
            f"({','.join('?' for _ in readers)})",
            conversation["id"], *readers,
        )
    except Exception as exc:
        app.logger.warning("Could not mark a conversation read: %s", exc)


def send_direct_message(conversation, sender, body):
    """Write one chat message into a thread, as ``sender``.

    No subject and no moderation context: this is a person typing at another
    person, and the thread is the subject.
    """
    return send_message(
        conversation_other_id(conversation, sender["id"]), "", body,
        sender=sender, kind="message", conversation_id=conversation["id"],
    )


def moderation_record(user_id, action, *, ban_kind=None, permanent=False, until=None,
                      reason=None, acted_by=None, content=None, message_id=None):
    """Write one line of the moderation log, or nothing when it is not there yet."""
    content = content or {}
    try:
        execute(
            """INSERT INTO moderation_log
                 (user_id, action, ban_kind, permanent, until, reason, acted_by,
                  content_kind, content_id, content_title, content_excerpt,
                  content_url, message_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            user_id, action, ban_kind, 1 if permanent else 0, until,
            (reason or "")[:BAN_REASON_MAX] or None, acted_by or None,
            content.get("kind"), content.get("id"), content.get("title"),
            content.get("excerpt"), content.get("url"), message_id,
        )
    except Exception as exc:
        app.logger.warning("Could not write the moderation log: %s", exc)


def moderation_content(kind, content_id):
    """The post or comment an admin attached to a ban, as a stored snapshot.

    Returns the ``about_*`` shape send_message() takes, or None when the id
    names nothing - which is why an admin can never attach a reference that does
    not exist, and why a notice only ever quotes something that was really
    written. The URL is stored alongside the text so the notice can link to the
    post (or the exact comment in it) even after the row itself has changed.
    """
    try:
        content_id = int(content_id)
    except (TypeError, ValueError):
        return None
    if kind == "comment":
        row = first("SELECT id, content, post_id FROM comments WHERE id=?", content_id)
        if not row:
            return None
        rows = fetch_posts("WHERE posts.id=?", (row["post_id"],))
        item = rows[0] if rows else None
        return {
            "kind": "comment",
            "id": row["id"],
            "title": (item or {}).get("title") or "a post",
            "excerpt": moderation_excerpt(row["content"]),
            "url": (canonical_post_path(item) + f"#comment-{row['id']}") if item else "",
        }
    if kind == "post":
        rows = fetch_posts("WHERE posts.id=?", (content_id,))
        if not rows:
            return None
        item = rows[0]
        return {
            "kind": "post",
            "id": item["id"],
            "title": item["title"] or "a post",
            "excerpt": moderation_excerpt(item["content"]),
            "url": canonical_post_path(item),
        }
    return None


def parse_moderation_content(value):
    """Read the admin form's ``post:12`` / ``comment:7`` value, if it names one."""
    kind, _, raw_id = (value or "").partition(":")
    if kind in ("post", "comment") and raw_id.isdigit():
        return moderation_content(kind, raw_id)
    return None


def ban_notice(target, kind, permanent, until, reason, content, actor):
    """The subject and body of the automatic message a ban sends.

    Written from the banned person's own point of view: what was decided, how
    long it lasts, what is still open to them, and - only when an admin actually
    gave them - the reason and the quoted content. Nothing is invented, so a
    notice never puts words in anybody's mouth.
    """
    lines = [f"Hello {target['display_name']},", ""]
    lines.append(ban_message(kind, {"permanent": permanent, "until": until}))
    lines.append(BAN_SCOPE_NOTES[kind])
    content = content or {}
    if content.get("id"):
        lines += ["", f"It is about your {content['kind']} on "
                      f"\"{content.get('title') or 'a post'}\":"]
        if content.get("excerpt"):
            lines.append(f"    \"{content['excerpt']}\"")
        lines.append("The full post is linked below.")
    lines.append("")
    if reason:
        lines += ["The administrator gave this reason:", f"    \"{reason}\""]
    else:
        lines.append("No reason was recorded with this ban.")
    lines += ["", f"Applied by: {actor}", ""]
    # A notice now arrives in a real conversation, so the person can simply reply
    # to it - which is what makes "if you think this is a mistake" actionable.
    lines.append("This notice was sent automatically by the site's moderation "
                 "account. Reply here if you think it is a mistake.")
    return BAN_SUBJECTS[kind], "\n".join(lines)


def unban_notice(target, kinds, actor):
    """The subject and body of the automatic message a lifted ban sends."""
    subject = "Your ban has been lifted" if len(kinds) == 1 else "Your bans have been lifted"
    areas = ", ".join(BAN_AREAS[kind] for kind in kinds)
    lines = [f"Hello {target['display_name']},", "",
             f"An administrator ({actor}) has lifted the ban on {areas} from your "
             "account.", "", "That means:"]
    for kind in kinds:
        lines.append(f"    - {UNBAN_NOTES[kind]}")
    lines += ["", "Sorry for the disruption, and welcome back."]
    return subject, "\n".join(lines)


def notice_conversation(target):
    """The thread notices to ``target`` belong in: their chat with the site.

    None when there is no moderation account to write as, or when migration 0015
    is not applied - which is what keeps a ban working either way, with the notice
    written unthreaded and the inbox listing it on its own.
    """
    account = moderation_account()
    if not account or account["id"] == target["id"]:
        return None
    return open_conversation(account["id"], target["id"])


def send_ban_notice(target, kind, permanent, until, reason, content, actor):
    """Tell the banned person what happened and why, then log the ban.

    The notice comes from the moderation *account*, not from the admin who applied
    it, so the admin is named inside the body instead: the site speaking and a
    person speaking should not look like the same thing. Because that account is a
    real one, the notice is an ordinary message in an ordinary thread, so the
    person can reply to it.

    Returns the message id, or None when the inbox could not be written to.
    """
    subject, body = ban_notice(target, kind, permanent, until, reason, content, actor)
    conversation = notice_conversation(target)
    message_id = send_message(
        target["id"], subject, body, kind="ban", about=content,
        ban={"kind": kind, "permanent": permanent, "until": until},
        conversation_id=(conversation or {}).get("id"),
    )
    moderation_record(
        target["id"], "ban", ban_kind=kind, permanent=permanent, until=until,
        reason=reason, acted_by=actor, content=content, message_id=message_id,
    )
    return message_id


def send_unban_notice(target, kinds, actor):
    """Tell the person their ban is over, and log the lift."""
    subject, body = unban_notice(target, kinds, actor)
    conversation = notice_conversation(target)
    message_id = send_message(
        target["id"], subject, body, kind="unban",
        conversation_id=(conversation or {}).get("id"),
    )
    for kind in kinds:
        moderation_record(target["id"], "unban", ban_kind=kind, acted_by=actor,
                          message_id=message_id)
    return message_id


def standalone_notices(user_id, limit=20):
    """Messages with no thread: a notice written when the site had no account to
    write it as. The inbox still shows these, which is what keeps a notice from
    migration 0014's era readable."""
    try:
        return query(
            "SELECT * FROM messages WHERE recipient_id=? AND conversation_id IS NULL "
            "ORDER BY id DESC LIMIT ?",
            user_id, limit,
        )
    except Exception as exc:
        app.logger.warning("Could not read standalone notices: %s", exc)
        return []


def latest_ban_notice(user_id, kind=None):
    """A person's newest ban notice, for the one page they can still open.

    An account ban cannot be read about in the inbox, because the inbox needs a
    session and the ban is what removes it - so the sign-in page shows the notice
    itself (see login()), which is also the only place the person is already
    proving they are who they say they are.
    """
    try:
        if kind:
            return first(
                "SELECT * FROM messages WHERE recipient_id=? AND kind='ban' "
                "AND ban_kind=? ORDER BY id DESC",
                user_id, kind,
            )
        return first(
            "SELECT * FROM messages WHERE recipient_id=? AND kind='ban' "
            "ORDER BY id DESC",
            user_id,
        )
    except Exception as exc:
        app.logger.warning("Could not read a ban notice for %s: %s", user_id, exc)
        return None


def message_for(user_id, message_id):
    """One message *belonging to* ``user_id``; nobody else's is ever returned."""
    try:
        return first(
            "SELECT * FROM messages WHERE id=? AND recipient_id=?",
            message_id, user_id,
        )
    except Exception as exc:
        app.logger.warning("Could not read message %s: %s", message_id, exc)
        return None


def message_by_id(message_id):
    """One message, with no owner check - callers must apply message_visible()."""
    try:
        return first("SELECT * FROM messages WHERE id=?", message_id)
    except Exception as exc:
        app.logger.warning("Could not read message %s: %s", message_id, exc)
        return None


def message_visible(item, user):
    """Who may open one message by its own address.

    Its recipient, always. An admin as well when the message is an old unthreaded
    notice, or when it belongs to the site's own conversation - that thread is the
    moderation account's, and an admin reads and answers it on its behalf because
    that account cannot sign in.
    """
    if not item or not user:
        return False
    if item.get("recipient_id") == user["id"]:
        return True
    if not is_admin():
        return False
    if not item.get("conversation_id"):
        return True
    return conversation_with_moderation(conversation_by_id(item["conversation_id"]))


def moderation_history(limit=40):
    """The newest moderation actions, newest first, for the admin panel."""
    try:
        return query(
            """SELECT moderation_log.*, users.username, users.display_name
               FROM moderation_log LEFT JOIN users ON users.id = moderation_log.user_id
               ORDER BY moderation_log.id DESC LIMIT ?""",
            limit,
        )
    except Exception as exc:
        app.logger.warning("Could not read the moderation log: %s", exc)
        return []


def moderation_threads(limit=25):
    """The site's own inbox, the way the admin panel sees it.

    Every thread the moderation account is in, newest first, with its unread count
    meaning "replies nobody has read yet". Read here rather than signed in as
    because that account has no session of its own - see conversation(), where an
    admin answers it on the site's behalf.
    """
    account = moderation_account()
    return conversations_for(account, limit=limit) if account else []


def inbox_threads(user, standing_in=False):
    """The conversation list down the left of the messages page.

    Whose threads those are depends on who is looking. Your own account's, which
    is the ordinary case; the site's, when an admin is reading the site's side of
    a thread - the list has to hold the conversation that is open, or the pane
    would be showing something the column beside it denies exists. A shared
    ADMIN_PASSWORD is not an account, so an admin with no session gets the site's
    list too rather than an empty column.
    """
    if user and not standing_in:
        return conversations_for(user)
    return moderation_threads()


def latest_ban_causes():
    """The newest ban per account, so the account list can say what caused it.

    The log is read newest first and the first row per account wins, which is
    exactly the ban that is in force now.
    """
    causes = {}
    try:
        rows = query("SELECT * FROM moderation_log WHERE action='ban' ORDER BY id DESC")
    except Exception as exc:
        app.logger.warning("Could not read ban causes: %s", exc)
        return causes
    for row in rows:
        causes.setdefault(row["user_id"], row)
    return causes


def valid_username(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,24}", value))


def safe_next(value, fallback):
    """A ``next`` target only if it stays on this site, else the fallback.

    Every ``next`` value this app writes is a root-relative path from ``url_for``,
    so anything else (``https://evil.example``, ``//evil.example``) is somebody
    hand-editing the form and is dropped rather than redirected to.
    """
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return fallback


def post_category_for(username):
    """Owner accounts post to the Systematics feed, everyone else to Community."""
    return "systematics" if is_owner_username(username) else "community"


def can_manage_post(item):
    """True for a post's own author and for site owners/admins."""
    if is_admin():
        return True
    user = current_user()
    return bool(user and item and item["user_id"] == user["id"])


def may_view(item):
    """Whether this viewer may open a post at all.

    Drafts are unlisted: their author and site owners can open them, else 404.
    A published post also has an audience now - public, one circle, or only its
    author - and a block hides both people from each other entirely.
    """
    if item["status"] != "published" and not can_manage_post(item):
        return False
    if not gplus_schema():
        return True
    if can_manage_post(item):
        return True
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    if viewer_id and is_blocked(viewer_id, item.get("user_id")):
        return False
    audience = item.get("audience") or "public"
    if audience == "public":
        return True
    if audience == "private":
        return False
    if audience == "circles" and viewer_id and item.get("circle_id"):
        return bool(safe_first(
            "SELECT 1 FROM circle_members WHERE circle_id=? AND user_id=?",
            item["circle_id"], viewer_id,
        ))
    return False


def fetch_posts(where="", params=(), limit=None, order="posts.created_at DESC"):
    """Post rows plus author, score, comment count and the viewer's own vote.

    The viewer id is bound first (0 for anonymous visitors, which matches no row),
    so ``params`` follows the WHERE clause placeholders.

    Everything migration 0016 added is read *only* when that migration is
    present. A database that has not had it applied yet still renders the feed,
    which matters because the GitHub Action ships code and never migrations: a
    deploy that lands first must degrade to the old feed instead of answering
    every page with error 1101.
    """
    viewer = session.get("user_db_id") or 0
    extra = []
    extra_joins = ""
    if gplus_schema():
        extra.extend([
            "(SELECT filename FROM post_images WHERE post_id=posts.id"
            " ORDER BY position, id LIMIT 1) AS cover_image",
            "(SELECT COUNT(*) FROM post_images WHERE post_id=posts.id) AS photo_count",
            "(SELECT COUNT(*) FROM shares WHERE post_id=posts.id) AS share_count",
            "shared.title AS shared_title",
            "shared.content AS shared_content",
            "shared.public_id AS shared_public_id",
            "shared.category AS shared_category",
            "shared_user.username AS shared_author_username",
            "shared_user.display_name AS shared_author_name",
            "shared_user.user_id AS shared_author_public_id",
        ])
        extra_joins += (
            "\n        LEFT JOIN posts shared ON shared.id = posts.share_of"
            "\n        LEFT JOIN users shared_user ON shared_user.id = shared.user_id"
        )
    else:
        extra.extend([
            "0 AS photo_count", "0 AS share_count",
            "NULL AS shared_title", "NULL AS shared_content",
            "NULL AS shared_public_id", "NULL AS shared_category",
            "NULL AS shared_author_username", "NULL AS shared_author_name",
            "NULL AS shared_author_public_id",
        ])
    if gplus2_schema():
        extra.extend([
            "pages.name AS page_name",
            "pages.slug AS page_slug",
            "pages.avatar AS page_avatar",
        ])
        extra_joins += "\n        LEFT JOIN pages ON pages.id = posts.page_id"
    extra_sql = ""
    if extra:
        extra_sql = ",\n               " + ",\n               ".join(extra)
    sql = f"""
        SELECT posts.*,
               users.username AS author_username,
               users.display_name AS author_display_name,
               users.profile_picture AS author_picture,
               users.user_id AS author_public_id,
               COALESCE((SELECT SUM(value) FROM post_votes WHERE post_id=posts.id), 0) AS score,
               (SELECT COUNT(*) FROM comments WHERE post_id=posts.id) AS comment_count,
               (SELECT value FROM post_votes WHERE post_id=posts.id AND user_id=?) AS my_vote,
               link_previews.title AS link_title,
               link_previews.description AS link_description,
               link_previews.image AS link_image,
               link_previews.site AS link_site,
               users.deleted_at AS author_deleted{extra_sql}
        FROM posts
        LEFT JOIN users ON users.id = posts.user_id
        LEFT JOIN link_previews ON link_previews.url = posts.link_url{extra_joins}
        {where}
        ORDER BY {order}
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return query(sql, viewer, *params)


POST_ID_LENGTH = 11
POST_ID_ALPHABET = string.ascii_letters + string.digits


def generate_post_public_id():
    """An unused public post id, in the shape Google+ used (``WU4Qec9X6os``).

    Ids are random rather than sequential so that a post's age and its
    neighbours cannot be worked out from its URL.
    """
    for _ in range(5):
        candidate = "".join(
            secrets.choice(POST_ID_ALPHABET) for _ in range(POST_ID_LENGTH)
        )
        if not first("SELECT id FROM posts WHERE public_id=?", candidate):
            return candidate
    return candidate  # 62**11 possibilities; the loop cannot really run dry


def next_profile_id():
    """The next account number: 1, 2, 3, ... in the order people signed up.

    Numbers are taken from the highest one in use rather than counted, so a
    number is never handed to two accounts and a number is never reused after a
    member leaves - an account's number is part of every post URL it owns.
    """
    row = first(
        "SELECT COALESCE(MAX(CAST(user_id AS INTEGER)), 0) + 1 AS next FROM users"
    )
    return str(row["next"])


def create_account(username, display_name, password_hash, picture):
    """Insert a new account, taking the next free account number.

    Two people registering in the same moment can read the same highest number,
    so the insert is attempted again: the UNIQUE constraint on users.user_id
    rejects the loser and the retry reads a fresh number. Five attempts is the
    same headroom the id generators above use.
    """
    for _ in range(5):
        public_id = next_profile_id()
        try:
            execute("""
                INSERT INTO users (user_id, username, display_name, password_hash, profile_picture)
                VALUES (?, ?, ?, ?, ?)
            """, public_id, username, display_name, password_hash, picture)
        except Exception:
            # Only a lost race is retried; anything else (a taken username, a
            # broken database) is the caller's problem.
            if first("SELECT id FROM users WHERE user_id=?", public_id):
                continue
            raise
        return first("SELECT * FROM users WHERE user_id=?", public_id)
    raise RuntimeError("could not allocate an account number")


def canonical_post_path(item):
    """A post's URL: ``/<account number>/posts/<post id>``.

    Google+ wrote its links in that shape, so the account of whoever wrote the
    post leads the address. The post is still looked up by its own id, and the
    leading segment is decoration: it is there to be read, and a stale one (an
    account id from before a migration, or somebody else's) is corrected with a
    redirect rather than served twice.
    """
    if not item.get("public_id"):
        # A row from before migration 0012 ran; its integer id still addresses it.
        return url_for("post_legacy", post_id=item["id"])
    author = item.get("author_public_id")
    if author:
        return url_for("post_with_author", author_id=author, public_id=item["public_id"])
    # The seeded welcome post has no author until an owner registers.
    return url_for("post", public_id=item["public_id"])


def post_path(post_id):
    """Canonical URL for a post id, or the feed when the post no longer exists."""
    rows = fetch_posts("WHERE posts.id=?", (post_id,))
    return canonical_post_path(rows[0]) if rows else url_for("home")


def follow_counts(user_id):
    """``(followers, following)`` totals for one account's profile header."""
    row = first(
        """SELECT (SELECT COUNT(*) FROM follows WHERE followed_id=?) AS followers,
                  (SELECT COUNT(*) FROM follows WHERE follower_id=?) AS following""",
        user_id, user_id,
    )
    if not row:
        return 0, 0
    return row["followers"] or 0, row["following"] or 0


def is_following(follower_id, followed_id):
    """True when ``follower_id`` follows ``followed_id`` (0 means anonymous)."""
    if not follower_id or not followed_id:
        return False
    return bool(first(
        "SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?",
        follower_id, followed_id,
    ))


def follow_list(user_id, direction, viewer_id=0, limit=FOLLOW_LIST_LIMIT):
    """The people following ``user_id``, or the people ``user_id`` follows.

    Each row carries the *viewer's* own follow state for that person, so a list of
    50 followers renders 50 correct buttons without 50 extra queries.
    """
    if direction == "following":
        selected, matched = "follows.followed_id", "follows.follower_id"
    else:
        selected, matched = "follows.follower_id", "follows.followed_id"
    return query(f"""
        SELECT users.id, users.username, users.display_name, users.profile_picture,
               users.bio, follows.created_at AS followed_at,
               (SELECT COUNT(*) FROM follows f WHERE f.followed_id=users.id)
                   AS follower_count,
               (SELECT COUNT(*) FROM posts
                 WHERE posts.user_id=users.id AND posts.status='published')
                   AS post_count,
               (SELECT COUNT(*) FROM follows mine
                 WHERE mine.follower_id=? AND mine.followed_id=users.id)
                   AS viewer_follows
        FROM follows
        JOIN users ON users.id = {selected}
        WHERE {matched}=?
        ORDER BY follows.created_at DESC, users.display_name COLLATE NOCASE
        LIMIT {int(limit)}
    """, viewer_id, user_id)


def viewer_follow_state(user):
    """Everything a profile header or follow button needs about one account."""
    viewer = current_user()
    viewers_id = viewer["id"] if viewer else 0
    followers, following = follow_counts(user["id"])
    return {
        "followers": followers,
        "following": following,
        "is_self": bool(viewer and viewer["id"] == user["id"]),
        "is_following": is_following(viewers_id, user["id"]),
        "viewer_id": viewers_id,
    }


def category_counts(viewer_id=None):
    """Published post totals per feed, for the home page tabs.

    Counted through the viewer's own visibility rule, so a private or circle post
    cannot be inferred from a tab's total.
    """
    counts = {name: 0 for name in POST_CATEGORIES}
    clause, params = visibility_sql(viewer_id)
    for row in query(
        f"SELECT posts.category, COUNT(*) AS total FROM posts"
        f" WHERE {clause} GROUP BY posts.category",
        *params,
    ):
        counts[row["category"]] = row["total"]
    counts["all"] = sum(counts.values())
    return counts


def comment_threads(post_id, viewer_id=0):
    """A post's comments as top-level rows, each carrying its ``replies`` list.

    Each comment carries its own +1 score and the viewer's own vote, so a thread
    renders every button correctly without asking the database again per row.
    """
    if gplus_schema():
        score_columns = """
               COALESCE((SELECT SUM(value) FROM comment_votes
                          WHERE comment_id=comments.id), 0) AS score,
               (SELECT value FROM comment_votes
                 WHERE comment_id=comments.id AND user_id=?) AS my_vote
        """
        params = (viewer_id, post_id)
    else:
        score_columns = " 0 AS score, NULL AS my_vote"
        params = (post_id,)
    rows = query(f"""
        SELECT comments.*, users.id AS author_id,
               users.user_id AS public_user_id,
               users.username, users.display_name, users.profile_picture,
               users.deleted_at AS author_deleted,
               {score_columns}
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE comments.post_id=?
        ORDER BY comments.created_at ASC
    """, *params)
    by_id = {row["id"]: row for row in rows}
    threads = []
    for row in rows:
        row["replies"] = []
    for row in rows:
        parent = by_id.get(row.get("parent_id"))
        if parent is not None and parent["id"] != row["id"]:
            parent["replies"].append(row)
        else:  # a reply whose parent was deleted becomes its own thread
            threads.append(row)
    return threads


# Google+ revival helpers ------------------------------------------------------
# The support for everything migration 0016 added. Two rules run through it:
#
#   * nothing reads a table or a column that migration adds unless the migration
#     is actually applied (gplus_schema() answers that once per request), because
#     the GitHub Action ships code and never migrations - a deploy that lands
#     before `npm run db:remote` must keep rendering the old site rather than
#     answering every page with Cloudflare error 1101;
#   * nothing here can fail a page. A notification that cannot be written is
#     logged, not raised: the like it was about has already been saved.
MENTION_RE = re.compile(r"(?<![\w@])@([A-Za-z0-9_]{3,24})")
# The `&` in the lookbehind matters: html.escape() turns an apostrophe into
# `&#x27;`, and without it the `#x27` inside that entity would be read as a tag
# called "x27" and turned into a link - every contraction on the site would
# sprout one. Entities are never tags.
HASHTAG_RE = re.compile(r"(?<![\w#&])#([A-Za-z0-9_]{1,40})")
# What a tagged handle is allowed to look like; the same rule users register
# under, so a post cannot create a link that no profile can answer.
MAX_FEED_TAG = 40


def gplus_schema():
    """True once migration 0016 is applied to the database.

    Asked by probing the column every revival feature depends on, and cached on
    ``g`` because a feed render asks several times.
    """
    if "gplus_schema" not in g:
        try:
            first("SELECT audience FROM posts LIMIT 1")
            g.gplus_schema = True
        except Exception:
            g.gplus_schema = False
    return g.gplus_schema


def safe_query(sql, *params):
    """query(), but a missing table returns [] instead of breaking the page."""
    try:
        return query(sql, *params)
    except Exception as exc:
        app.logger.warning("Optional query failed: %s", exc)
        return []


def safe_first(sql, *params):
    """first(), but a missing table returns None instead of breaking the page."""
    try:
        return first(sql, *params)
    except Exception as exc:
        app.logger.warning("Optional lookup failed: %s", exc)
        return None


def safe_execute(sql, *params):
    """execute(), but a missing table is logged instead of raised."""
    try:
        execute(sql, *params)
        return True
    except Exception as exc:
        app.logger.warning("Optional write failed: %s", exc)
        return False


# Blocking --------------------------------------------------------------------

def blocked_ids(user_id):
    """Every account ``user_id`` blocks or is blocked by, in either direction.

    G+ made a block mutual invisibility, and so does this: one query answers both
    halves so a feed can exclude the lot at once.
    """
    if not user_id or not gplus_schema():
        return set()
    rows = safe_query(
        "SELECT blocked_id AS other FROM blocks WHERE blocker_id=?"
        " UNION SELECT blocker_id FROM blocks WHERE blocked_id=?",
        user_id, user_id,
    )
    return {row["other"] for row in rows}


def is_blocked(first_id, second_id):
    """True when either account has blocked the other."""
    if not first_id or not second_id or not gplus_schema():
        return False
    return bool(safe_first(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?)"
        " OR (blocker_id=? AND blocked_id=?)",
        first_id, second_id, second_id, first_id,
    ))


def viewer_blocks(user, other_id):
    """Whether the signed-in viewer has blocked ``other_id`` (not the reverse)."""
    return bool(user and other_id and safe_first(
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?",
        user["id"], other_id,
    ))


# Who may see a post ------------------------------------------------------------

def visibility_sql(viewer_id=None, alias="posts"):
    """A WHERE clause for the posts one viewer is allowed to see.

    A public post is public; a circle post is visible to its author and to the
    members of that circle; "only me" is visible to nobody else. Blocked accounts
    disappear in both directions. Drafts are never in a stream - they are opened
    through may_view(), which is the only other gate.
    """
    if viewer_id is None:
        viewer_id = session.get("user_db_id") or 0
    if not gplus_schema():
        return f"({alias}.status='published')", []
    clause = (
        f"({alias}.status='published' AND ({alias}.audience='public'"
        f" OR {alias}.user_id=?"
        f" OR ({alias}.audience='circles' AND {alias}.circle_id IN"
        f" (SELECT circle_id FROM circle_members WHERE user_id=?))))"
    )
    params = [viewer_id, viewer_id]
    if viewer_id:
        clause += (
            f" AND NOT EXISTS (SELECT 1 FROM blocks b"
            f" WHERE (b.blocker_id=? AND b.blocked_id={alias}.user_id)"
            f" OR (b.blocker_id={alias}.user_id AND b.blocked_id=?))"
        )
        params += [viewer_id, viewer_id]
        # A muted account leaves the streams but not the site: their profile still
        # opens, and so does a post opened by its own address. This is the softer
        # control G+ put beside Block.
        if gplus2_schema():
            clause += (
                f" AND NOT EXISTS (SELECT 1 FROM user_mutes um"
                f" WHERE um.muter_id=? AND um.muted_id={alias}.user_id)"
            )
            params.append(viewer_id)
    return clause, params


def audience_label(item):
    """How a post's audience is worded on its own page and in the editor."""
    audience = (item or {}).get("audience") or "public"
    if audience == "circles" and (item or {}).get("circle_name"):
        return item["circle_name"]
    return AUDIENCE_LABELS.get(audience, "Public")


def circle_for_post(item):
    """The circle a post was shared to, when there is one to name."""
    if not item or not item.get("circle_id") or not gplus_schema():
        return None
    return safe_first("SELECT * FROM circles WHERE id=?", item["circle_id"])


# Notifications -----------------------------------------------------------------

def notify(user_id, kind, actor_id=None, post_id=None, comment_id=None):
    """Tell ``user_id`` that ``actor_id`` did ``kind`` to something of theirs.

    Skips the actor's own actions (nobody wants a bell for liking their own
    post), skips blocked accounts, and skips a post the recipient has muted. A
    write that fails is logged and lost - the action it describes is already
    saved, and a notification is never worth failing a request over.
    """
    if not user_id or not gplus_schema():
        return False
    if actor_id and int(actor_id) == int(user_id):
        return False
    if actor_id and is_blocked(user_id, actor_id):
        return False
    if post_id:
        muted = safe_first(
            "SELECT 1 FROM post_mutes WHERE post_id=? AND user_id=?",
            post_id, user_id,
        )
        if muted:
            return False
    # A per-kind switch (migration 0017) and, if the account asked for it, one
    # line in the email outbox. Both are read at notify time, so turning a kind
    # off stops the next one rather than hiding a row that already exists.
    recipient = None
    if gplus2_schema():
        recipient = safe_first("SELECT * FROM users WHERE id=?", user_id)
        if recipient and not notification_prefs(recipient).get(kind, True):
            return False
    inserted = safe_execute(
        "INSERT INTO notifications (user_id, kind, actor_id, post_id, comment_id)"
        " VALUES (?, ?, ?, ?, ?)",
        user_id, kind, actor_id, post_id, comment_id,
    )
    if inserted and recipient is not None and actor_id:
        actor = safe_first(
            "SELECT display_name, username FROM users WHERE id=?", actor_id
        )
        who = (actor or {}).get("display_name") or "Somebody"
        sentence = {
            "like": f"{who} +1'd your post.",
            "comment": f"{who} commented on your post.",
            "reply": f"{who} replied to your comment.",
            "mention": f"{who} mentioned you.",
            "follow": f"{who} started following you.",
            "share": f"{who} shared your post.",
            "comment_like": f"{who} +1'd your comment.",
            "tag": f"{who} tagged you in a post.",
        }.get(kind, f"{who} did something on your account.")
        queue_email(
            recipient, kind, f"{who} on Systematics Black MIDI",
            sentence + "\n\nOpen the site to see it: https://systematics-bm.systematic-midis.workers.dev/notifications",
        )
    return inserted


def unread_notifications(user):
    """How many of ``user``'s notifications are unread, for the rail badge."""
    if not user or not gplus_schema():
        return 0
    row = safe_first(
        "SELECT COUNT(*) AS total FROM notifications"
        " WHERE user_id=? AND read_at IS NULL",
        user["id"],
    )
    return int(row["total"]) if row else 0


def notification_rows(user_id, limit=NOTIFICATION_PAGE_SIZE):
    """The newest notifications with everything needed to word one."""
    if not user_id or not gplus_schema():
        return []
    rows = safe_query(f"""
        SELECT notifications.*,
               actor.username AS actor_username,
               actor.display_name AS actor_display_name,
               actor.profile_picture AS actor_picture,
               actor.deleted_at AS actor_deleted,
               posts.title AS post_title,
               posts.public_id AS post_public_id,
               posts.user_id AS post_user_id,
               comments.content AS comment_content
        FROM notifications
        LEFT JOIN users actor ON actor.id = notifications.actor_id
        LEFT JOIN posts ON posts.id = notifications.post_id
        LEFT JOIN comments ON comments.id = notifications.comment_id
        WHERE notifications.user_id=?
        ORDER BY notifications.id DESC
        LIMIT {int(limit)}
    """, user_id)
    return rows


def notification_text(row):
    """The sentence one notification shows, written from the reader's side."""
    actor = row.get("actor_display_name") or "Somebody"
    kind = row.get("kind")
    if kind == "like":
        return f"{actor} +1'd your post"
    if kind == "comment":
        return f"{actor} commented on your post"
    if kind == "reply":
        return f"{actor} replied to your comment"
    if kind == "mention":
        return f"{actor} mentioned you"
    if kind == "follow":
        return f"{actor} started following you"
    if kind == "share":
        return f"{actor} shared your post"
    if kind == "comment_like":
        return f"{actor} +1'd your comment"
    if kind == "tag":
        return f"{actor} tagged you in a post"
    return f"{actor} did something on your post"


def notification_url(row):
    """Where a notification goes: the post, the comment, or the actor."""
    if row.get("post_public_id"):
        post_row = {"public_id": row["post_public_id"],
                    "author_public_id": row.get("actor_public_id") or row.get("post_user_id")}
        base = url_for("post", public_id=row["post_public_id"])
        if row.get("comment_id"):
            base += f"#comment-{row['comment_id']}"
        return base
    if row.get("actor_username"):
        return url_for("profile", username=row["actor_username"])
    return url_for("notifications")


def notify_mentions(text, actor, post_id=None, comment_id=None):
    """Tell every @handle mentioned in ``text``, once each.

    Handles are looked up, so text that happens to contain an @ does not create a
    notification for a name that does not exist.
    """
    if not text or not actor or not gplus_schema():
        return
    seen = set()
    for match in MENTION_RE.finditer(text):
        username = match.group(1)
        if username.lower() in seen:
            continue
        seen.add(username.lower())
        target = safe_first(
            "SELECT id, username FROM users WHERE username=? COLLATE NOCASE",
            username,
        )
        if target and target["id"] != actor["id"]:
            notify(target["id"], "mention", actor["id"], post_id, comment_id)


# Hashtags ----------------------------------------------------------------------

def tags_in(text):
    """Every #tag in a body, lowercased and de-duplicated, in first-use order."""
    tags = []
    seen = set()
    for match in HASHTAG_RE.finditer(text or ""):
        tag = match.group(1).lower()
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags[:20]


def store_post_tags(post_id, content):
    """Replace a post's stored tags with the ones its body now carries."""
    if not gplus_schema():
        return
    safe_execute("DELETE FROM post_tags WHERE post_id=?", post_id)
    for tag in tags_in(content):
        safe_execute(
            "INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)",
            post_id, tag,
        )


def top_tags(limit=12, days=90):
    """The tags in most use lately, which is what the trending strip shows."""
    if not gplus_schema():
        return []
    return safe_query(f"""
        SELECT post_tags.tag, COUNT(*) AS uses
        FROM post_tags JOIN posts ON posts.id = post_tags.post_id
        WHERE posts.status='published'
          AND posts.created_at >= datetime('now', '-{int(days)} days')
        GROUP BY post_tags.tag
        ORDER BY uses DESC, post_tags.tag
        LIMIT {int(limit)}
    """)


# Circles -----------------------------------------------------------------------

def circle_rows(user_id):
    """An account's circles with how many people are in each."""
    if not user_id or not gplus_schema():
        return []
    return safe_query("""
        SELECT circles.*,
               (SELECT COUNT(*) FROM circle_members
                 WHERE circle_id=circles.id) AS member_count
        FROM circles WHERE circles.user_id=?
        ORDER BY circles.name COLLATE NOCASE
    """, user_id)


def circle_by_id(circle_id):
    return safe_first("SELECT * FROM circles WHERE id=?", circle_id)


def circle_member_rows(circle_id, limit=MAX_CIRCLE_MEMBERS):
    if not gplus_schema():
        return []
    return safe_query(f"""
        SELECT users.id, users.username, users.display_name, users.profile_picture,
               users.bio, users.deleted_at
        FROM circle_members JOIN users ON users.id = circle_members.user_id
        WHERE circle_members.circle_id=?
        ORDER BY circle_members.added_at DESC
        LIMIT {int(limit)}
    """, circle_id)


def circle_of_author_for(viewer_id, author_id):
    """Is ``author_id`` in one of the viewer's circles? (for the profile badge)"""
    if not viewer_id or not author_id or not gplus_schema():
        return None
    return safe_first("""
        SELECT circles.name FROM circles
        JOIN circle_members ON circle_members.circle_id = circles.id
        WHERE circles.user_id=? AND circle_members.user_id=?
        ORDER BY circles.name LIMIT 1
    """, viewer_id, author_id)


# Collections --------------------------------------------------------------------

def collection_rows(user_id, viewer_id=0):
    """An account's collections, with the public post counts beside them."""
    if not user_id or not gplus_schema():
        return []
    rows = safe_query("""
        SELECT collections.*,
               (SELECT COUNT(*) FROM posts
                 WHERE posts.collection_id=collections.id
                   AND posts.status='published') AS post_count
        FROM collections WHERE collections.user_id=?
        ORDER BY collections.name COLLATE NOCASE
    """, user_id)
    if user_id != viewer_id:
        rows = [row for row in rows if row["post_count"]]
    return rows


def collection_by_id(collection_id):
    return safe_first("SELECT * FROM collections WHERE id=?", collection_id)


# Communities ---------------------------------------------------------------------

def community_rows(viewer_id=0):
    """Every community, newest first, with member and post counts."""
    if not gplus_schema():
        return []
    return safe_query("""
        SELECT communities.*,
               users.username AS owner_username,
               users.display_name AS owner_name,
               (SELECT COUNT(*) FROM community_members
                 WHERE community_id=communities.id) AS member_count,
               (SELECT COUNT(*) FROM posts
                 WHERE community_id=communities.id
                   AND status='published') AS post_count,
               (SELECT role FROM community_members
                 WHERE community_id=communities.id AND user_id=?) AS my_role
        FROM communities
        JOIN users ON users.id = communities.owner_id
        ORDER BY communities.created_at DESC, communities.id DESC
    """, viewer_id)


def communities_for(user_id):
    """The communities an account belongs to, for the editor's picker."""
    if not user_id or not gplus_schema():
        return []
    return safe_query("""
        SELECT communities.*, community_members.role
        FROM community_members
        JOIN communities ON communities.id = community_members.community_id
        WHERE community_members.user_id=?
        ORDER BY communities.name COLLATE NOCASE
    """, user_id)


def community_by_slug(slug):
    return safe_first("SELECT * FROM communities WHERE slug=? COLLATE NOCASE", slug)


def community_membership(community_id, user_id):
    if not community_id or not user_id or not gplus_schema():
        return None
    return safe_first(
        "SELECT * FROM community_members WHERE community_id=? AND user_id=?",
        community_id, user_id,
    )


# Events --------------------------------------------------------------------------

def event_rows(limit=30):
    if not gplus_schema():
        return []
    return safe_query(f"""
        SELECT events.*, users.username AS owner_username,
               users.display_name AS owner_name,
               (SELECT COUNT(*) FROM event_attendees
                 WHERE event_id=events.id AND status='going') AS going_count
        FROM events JOIN users ON users.id = events.owner_id
        ORDER BY events.starts_at ASC
        LIMIT {int(limit)}
    """)


def event_by_id(event_id):
    return safe_first("SELECT * FROM events WHERE id=?", event_id)


def event_attendance(event_id, user_id):
    if not event_id or not user_id or not gplus_schema():
        return None
    return safe_first(
        "SELECT * FROM event_attendees WHERE event_id=? AND user_id=?",
        event_id, user_id,
    )


# Photos and media ----------------------------------------------------------------

def post_image_rows(post_id):
    """A post's images in the order they were uploaded."""
    if not post_id or not gplus_schema():
        return []
    return safe_query(
        "SELECT * FROM post_images WHERE post_id=? ORDER BY position, id", post_id
    )


def post_people_rows(post_id):
    if not post_id or not gplus_schema():
        return []
    return safe_query("""
        SELECT users.id, users.username, users.display_name
        FROM post_people JOIN users ON users.id = post_people.user_id
        WHERE post_people.post_id=?
    """, post_id)


def photo_posts_of(user_id, tagged=False):
    """Posts with photos by ``user_id`` - or, tagged, posts they appear in."""
    if not gplus_schema():
        return []
    clause, params = visibility_sql(session.get("user_db_id") or 0)
    if tagged:
        where = (
            f"{clause} AND posts.id IN (SELECT post_id FROM post_people WHERE user_id=?)"
        )
        params = params + [user_id]
    else:
        where = f"{clause} AND posts.user_id=? AND posts.id IN (SELECT post_id FROM post_images)"
        params = params + [user_id]
    return fetch_posts("WHERE " + where, tuple(params), order="posts.created_at DESC")


YOUTUBE_RE = re.compile(
    r"(?:youtube\.com/(?:watch\?[^\s#]*v=|shorts/|embed/)|youtu\.be/)([A-Za-z0-9_-]{6,20})",
    re.IGNORECASE,
)


def embed_for(url):
    """An inline player for a YouTube or SoundCloud link, or None.

    G+ expanded a pasted video into a playable thing; this is the same idea for
    the two services this site's posts actually use. Only a player is built from
    a *known* host and an id-shaped value, never from the URL itself, so a link
    cannot smuggle an arbitrary frame into a page.
    """
    if not url:
        return None
    match = YOUTUBE_RE.search(url)
    if match:
        return {"kind": "youtube", "src": f"https://www.youtube.com/embed/{match.group(1)}"}
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if host in ("soundcloud.com", "www.soundcloud.com", "m.soundcloud.com"):
        from urllib.parse import quote
        return {
            "kind": "soundcloud",
            "src": "https://w.soundcloud.com/player/?url="
                   + quote(url, safe="") + "&color=%234285f4&visual=true",
        }
    return None


# Reshares ------------------------------------------------------------------------

def share_count(post_id):
    if not gplus_schema():
        return 0
    row = safe_first("SELECT COUNT(*) AS total FROM shares WHERE post_id=?", post_id)
    return int(row["total"]) if row else 0


def shares_of(post_id):
    if not gplus_schema():
        return []
    return safe_query("""
        SELECT users.username, users.display_name, users.profile_picture,
               shares.created_at, shares.post_id_created
        FROM shares JOIN users ON users.id = shares.user_id
        WHERE shares.post_id=?
        ORDER BY shares.created_at DESC
        LIMIT 50
    """, post_id)


def voters_of(post_id, value=1, limit=30):
    """Who +1'd a post, for the "who liked this" list."""
    if not gplus_schema():
        return []
    return safe_query(f"""
        SELECT users.username, users.display_name, users.profile_picture,
               post_votes.created_at
        FROM post_votes JOIN users ON users.id = post_votes.user_id
        WHERE post_votes.post_id=? AND post_votes.value=?
        ORDER BY post_votes.created_at DESC LIMIT {int(limit)}
    """, post_id, value)


# The rest of Google+: pages, mutes, mail, albums, hangouts and sparks ----------

def gplus2_schema():
    """True once migration 0017 is applied (and 0016, which it builds on)."""
    if "gplus2_schema" not in g:
        if not gplus_schema():
            g.gplus2_schema = False
        else:
            try:
                first("SELECT 1 FROM pages LIMIT 1")
                g.gplus2_schema = True
            except Exception:
                g.gplus2_schema = False
    return g.gplus2_schema


# Muting a person ---------------------------------------------------------------
def muted_ids(user_id):
    """Accounts ``user_id`` has muted. Muted posts leave the streams, not the site."""
    if not user_id or not gplus2_schema():
        return set()
    return {row["muted_id"] for row in safe_query(
        "SELECT muted_id FROM user_mutes WHERE muter_id=?", user_id
    )}


def is_muted(muter_id, muted_id):
    if not muter_id or not muted_id or not gplus2_schema():
        return False
    return bool(safe_first(
        "SELECT 1 FROM user_mutes WHERE muter_id=? AND muted_id=?",
        muter_id, muted_id,
    ))


def muted_people(user_id):
    """The accounts ``user_id`` mutes, for the settings page."""
    if not user_id or not gplus2_schema():
        return []
    return safe_query("""
        SELECT users.id, users.username, users.display_name, users.profile_picture
        FROM user_mutes JOIN users ON users.id = user_mutes.muted_id
        WHERE user_mutes.muter_id=?
        ORDER BY users.display_name COLLATE NOCASE
    """, user_id)


# Notification preferences and email ---------------------------------------------
def notification_prefs(user):
    """The account's per-kind switches; a missing key means on."""
    prefs = {kind: True for kind in NOTIFICATION_KINDS}
    if not user or not gplus2_schema():
        return prefs
    raw = user.get("notification_prefs")
    if not raw:
        return prefs
    try:
        stored = json.loads(raw)
    except (TypeError, ValueError):
        return prefs
    if isinstance(stored, dict):
        for kind in NOTIFICATION_KINDS:
            if kind in stored:
                prefs[kind] = bool(stored[kind])
    return prefs


def email_config():
    """Where queued mail is sent, from Worker variables/secrets.

    A Resend-compatible endpoint is assumed (`POST {from,to,subject,text}` with a
    bearer token). Nothing is sent until all three values exist, which is why the
    site works - and shows "not configured" - with no mail provider at all.
    """
    try:
        worker_env = env()
    except Exception:
        worker_env = None
    def value(name, fallback=""):
        configured = getattr(worker_env, name, None) if worker_env is not None else None
        return (configured or os.environ.get(name) or fallback).strip()
    return {
        "url": value("EMAIL_API_URL", DEFAULT_EMAIL_API_URL),
        "key": value("EMAIL_API_KEY"),
        "from": value("EMAIL_FROM"),
    }


def email_configured():
    cfg = email_config()
    return bool(cfg["url"] and cfg["key"] and cfg["from"])


def queue_email(recipient, kind, subject, body):
    """Put one digest line in the outbox for an account that asked for email."""
    if not gplus2_schema() or not recipient:
        return False
    address = (recipient.get("email") or "").strip()
    if not address or not recipient.get("email_digest"):
        return False
    return safe_execute(
        "INSERT INTO email_outbox (recipient_id, to_address, kind, subject, body)"
        " VALUES (?, ?, ?, ?, ?)",
        recipient["id"], address, kind, subject, body,
    )


def pending_email_count():
    if not gplus2_schema():
        return 0
    row = safe_first(
        "SELECT COUNT(*) AS total FROM email_outbox WHERE sent_at IS NULL"
    )
    return int(row["total"]) if row else 0


def flush_emails(limit=EMAIL_BATCH_SIZE):
    """Send the oldest queued emails; returns ``(sent, message)``.

    Called from the admin panel, never from the request that caused a
    notification: a mail provider can take seconds, and the Worker's CPU budget is
    spent before that returns. A failure leaves the row pending with its error so
    the admin can see what happened and try again.
    """
    cfg = email_config()
    if not email_configured():
        return 0, ("Email is not configured. Set EMAIL_API_KEY, EMAIL_FROM and "
                   "(optionally) EMAIL_API_URL as Worker secrets/variables.")
    if not gplus2_schema():
        return 0, "Email needs migration 0017 applied to the database."
    rows = safe_query(
        "SELECT * FROM email_outbox WHERE sent_at IS NULL ORDER BY id LIMIT ?",
        int(limit),
    )
    sent = 0
    for row in rows:
        init = {
            "method": "POST",
            "headers": {
                "authorization": f"Bearer {cfg['key']}",
                "content-type": "application/json",
            },
            "body": json.dumps({
                "from": cfg["from"],
                "to": [row["to_address"]],
                "subject": row["subject"],
                "text": row["body"],
            }),
        }
        try:
            response = run_sync(http_fetch()(cfg["url"], to_js(init)))
            status = int(response.status)
            if status < 400:
                safe_execute(
                    "UPDATE email_outbox SET sent_at=datetime('now'), error=NULL"
                    " WHERE id=?", row["id"],
                )
                sent += 1
            else:
                safe_execute(
                    "UPDATE email_outbox SET error=? WHERE id=?",
                    f"provider answered HTTP {status}", row["id"],
                )
        except Exception as exc:
            safe_execute(
                "UPDATE email_outbox SET error=? WHERE id=?", str(exc)[:300], row["id"]
            )
    return sent, f"Sent {sent} of {len(rows)} queued email(s)." if rows else "Nothing queued."


# Pages -------------------------------------------------------------------------
def page_by_slug(slug):
    if not gplus2_schema():
        return None
    return safe_first("SELECT * FROM pages WHERE slug=? COLLATE NOCASE", slug)


def page_by_id(page_id):
    if not gplus2_schema():
        return None
    return safe_first("SELECT * FROM pages WHERE id=?", page_id)


def pages_for(user_id):
    """Pages ``user_id`` may write as, for the composer's identity picker."""
    if not user_id or not gplus2_schema():
        return []
    return safe_query("""
        SELECT pages.* FROM pages
        JOIN page_managers ON page_managers.page_id = pages.id
        WHERE page_managers.user_id=?
        ORDER BY pages.name COLLATE NOCASE
    """, user_id)


def page_managers_rows(page_id):
    if not gplus2_schema():
        return []
    return safe_query("""
        SELECT users.id, users.username, users.display_name, users.profile_picture,
               page_managers.role
        FROM page_managers JOIN users ON users.id = page_managers.user_id
        WHERE page_managers.page_id=?
        ORDER BY page_managers.added_at
    """, page_id)


def can_manage_page(page, user):
    if not page or not user or not gplus2_schema():
        return False
    if page["owner_id"] == user["id"]:
        return True
    return bool(safe_first(
        "SELECT 1 FROM page_managers WHERE page_id=? AND user_id=?",
        page["id"], user["id"],
    ))


def page_rows(limit=50):
    if not gplus2_schema():
        return []
    return safe_query(f"""
        SELECT pages.*,
               users.username AS owner_username,
               (SELECT COUNT(*) FROM posts
                 WHERE posts.page_id=pages.id AND posts.status='published') AS post_count
        FROM pages JOIN users ON users.id = pages.owner_id
        ORDER BY pages.name COLLATE NOCASE LIMIT {int(limit)}
    """)


def page_posts(page, viewer_id=None, limit=40):
    clause, params = visibility_sql(viewer_id)
    return fetch_posts(
        f"WHERE {clause} AND posts.page_id=?",
        tuple(params + [page["id"]]), order="posts.id DESC", limit=limit,
    )


# Albums -------------------------------------------------------------------------
def albums_for(user_id, viewer_id=0):
    """An account's albums with their post counts; empty ones are private."""
    if not user_id or not gplus2_schema():
        return []
    rows = safe_query("""
        SELECT albums.*,
               (SELECT COUNT(*) FROM album_posts WHERE album_id=albums.id) AS post_count
        FROM albums WHERE albums.user_id=?
        ORDER BY albums.name COLLATE NOCASE
    """, user_id)
    if user_id != viewer_id:
        rows = [row for row in rows if row["post_count"]]
    return rows


def album_by_id(album_id):
    if not gplus2_schema():
        return None
    return safe_first("SELECT * FROM albums WHERE id=?", album_id)


def album_posts(album_id):
    clause, params = visibility_sql()
    return fetch_posts(
        f"WHERE {clause} AND posts.id IN"
        f" (SELECT post_id FROM album_posts WHERE album_id=?)",
        tuple(params + [album_id]), order="posts.id DESC", limit=60,
    )


def post_album_rows(post_id):
    if not gplus2_schema():
        return []
    return safe_query("""
        SELECT albums.* FROM albums
        JOIN album_posts ON album_posts.album_id = albums.id
        WHERE album_posts.post_id=? ORDER BY albums.name COLLATE NOCASE
    """, post_id)


# Hangouts ------------------------------------------------------------------------
def hangout_rows(limit=30):
    if not gplus2_schema():
        return []
    return safe_query(f"""
        SELECT hangouts.*, users.username AS owner_username,
               users.display_name AS owner_name
        FROM hangouts JOIN users ON users.id = hangouts.owner_id
        WHERE hangouts.ended_at IS NULL
        ORDER BY hangouts.created_at DESC, hangouts.id DESC LIMIT {int(limit)}
    """)


def hangout_by_room(room):
    if not gplus2_schema():
        return None
    return safe_first("SELECT * FROM hangouts WHERE room=?", room)


def hangout_by_id(hangout_id):
    if not gplus2_schema():
        return None
    return safe_first("SELECT * FROM hangouts WHERE id=?", hangout_id)


def jitsi_room_name():
    """A room nobody can guess, on Jitsi's free public service."""
    return "SystematicsBM-" + secrets.token_hex(8)


# Sparks --------------------------------------------------------------------------
def spark_rows(limit=50):
    if not gplus2_schema():
        return []
    return safe_query(f"""
        SELECT sparks.*,
               (SELECT COUNT(*) FROM spark_links WHERE spark_id=sparks.id)
                   AS link_count
        FROM sparks ORDER BY sparks.name COLLATE NOCASE LIMIT {int(limit)}
    """)


def spark_by_slug(slug):
    if not gplus2_schema():
        return None
    return safe_first("SELECT * FROM sparks WHERE slug=? COLLATE NOCASE", slug)


def spark_link_rows(spark_id, limit=60):
    if not gplus2_schema():
        return []
    return safe_query(f"""
        SELECT spark_links.*,
               users.username AS added_by_username,
               users.display_name AS added_by_name,
               link_previews.title, link_previews.description,
               link_previews.image, link_previews.site
        FROM spark_links
        LEFT JOIN users ON users.id = spark_links.added_by
        LEFT JOIN link_previews ON link_previews.url = spark_links.url
        WHERE spark_links.spark_id=?
        ORDER BY spark_links.id DESC LIMIT {int(limit)}
    """, spark_id)


def youtube_id(url):
    """The id of a YouTube video, live page, short or embed, or None."""
    match = re.search(
        r"(?:youtube\.com/(?:watch\?[^\s#]*v=|shorts/|embed/|live/)|youtu\.be/)"
        r"([A-Za-z0-9_-]{6,20})",
        url or "", re.IGNORECASE,
    )
    return match.group(1) if match else None


# Link cards -----------------------------------------------------------------

META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
ATTR_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"""
)
TITLE_TAG_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"'\]\[]+", re.IGNORECASE)


# Hyperlinks in user text -----------------------------------------------------
# Post bodies, comments and bios are plain text. Everything a person typed is
# escaped, and only whole URLs become anchors, so a body containing markup is
# still shown as the characters somebody wrote instead of being rendered.
# ``www.`` is matched as well as a scheme: people paste "www.mediafire.com/..."
# and expect it to be clickable.
# Two ways to make a link, matched in one pass so that the address inside the
# bracket form is never also matched as a bare URL:
#
#   https://mediafire.com/file/...     the whole address is its own link text
#   [Armageddon Black MIDI](https://mediafire.com/file/...)   the text is the link
#
# The second form only picks the address out of brackets - nothing else of
# Markdown is implemented, and the label is the only thing a reader sees, so a
# pasted address stops shouting its way through a sentence. The address has to
# start with a scheme or "www.", which is also what keeps a hand-written
# ``[click](javascript:...)`` from becoming an anchor.
LINK_IN_TEXT_RE = re.compile(
    r"\[([^\[\]\n]+)\]\(\s*((?:https?://|www\.)[^\s()<>\"']+)\s*\)"
    r"|((?:https?://|www\.)[^\s<>\"']+)",
    re.IGNORECASE,
)
# Sentence punctuation sitting at the end of a bare match belongs to the
# sentence, not to the URL ("...download it at https://example.com/x."). The
# bracket form needs none of this: its closing paren is the end of the address.
LINK_TRAILING_PUNCTUATION = ".,;:!?'\")"
# An excerpt can stop inside a bracket link, which would leave the reader looking
# at a stray "[" or half an address. Only the label survives a cut, because that
# is the part meant to be read and an address with its tail missing is not a
# link. Two shapes of cut, one rule: the label runs to the end, sometimes with
# the unfinished "](address" still hanging off it. A bracket that does close -
# "[1]" at the end of a post - cannot match, so ordinary text keeps its brackets.
MD_LINK_TAIL_RE = re.compile(
    r"\[([^\[\]\n]*)(?:\]\((?:https?://|www\.)[^\s()<>\"']*)?$"
)


# Google+ never resolved this pair of placeholders: its notification mails went
# out carrying the string "[DATE] at [LOCAL USER TIME ZONE]" literally. A post is
# allowed to write them, and linkify() fills them in from the post's own
# timestamp.
#
# The word "at" between the two is part of that phrase, so the pair collapses
# into a single stamp - otherwise removing the zone would leave the "at" stranded
# at the end of the line. The stamp itself is UTC here; public/static/localtime.js
# restates it in the reader's own zone, which only the browser knows.
#
# The zone is no longer printed as a name. "9:07 pm at America/Chicago" said more
# about the reader's settings than about the post, so the bare token now renders
# as nothing at all - it still matches, which is what keeps a post written while
# it did print the name from showing raw brackets.
LOG_PHRASE_RE = re.compile(r"\[date\]\s+at\s+\[local user time zone\]", re.IGNORECASE)
LOG_TOKEN_RE = re.compile(
    r"\[date\]|\[local user time zone\]|\[commits\]", re.IGNORECASE
)
LOG_DATE_TOKEN = "[date]"
# [COMMITS] is filled in from GitHub; see the commit log section below.
LOG_COMMITS_TOKEN = "[commits]"


def log_time_html(stamp):
    """One timestamp as the markup localtime.js restates in the reader's zone."""
    iso, text = stamp
    return f'<time class="log-time" datetime="{iso}" data-log-time="{iso}">{text}</time>'


def log_stamp(created_at):
    """``(iso, text)`` for one post's timestamp, or None when it has none.

    The text is a 12-hour clock (``2026-09-19 9:07 pm``) rather than the site's
    usual 24-hour one, because this is a line of prose in a post - the way the
    date it replaces was written.
    """
    when = db_time(created_at)
    if when is None:
        return None
    hour = when.hour % 12 or 12
    half = "am" if when.hour < 12 else "pm"
    return (
        when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        f"{when.strftime('%Y-%m-%d')} {hour}:{when.strftime('%M')} {half}",
    )


BOLD_IN_TEXT_RE = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.DOTALL)
STRIKE_IN_TEXT_RE = re.compile(r"~~(?=\S)(.+?)(?<=\S)~~", re.DOTALL)
ITALIC_IN_TEXT_RE = re.compile(
    r"(?<![\w*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])", re.DOTALL
)


def decorate_text(escaped):
    """Turn **bold**, ~~strike~~, *italic*, @mentions and #tags into markup.

    Runs *after* escaping and only on plain runs of text, so the input is already
    someone's words rather than HTML. Every address it writes is built with
    url_for from a value the regex has already constrained (a handle shaped like
    a real username, a tag of letters, digits or underscores), which is what
    keeps a post from inventing a link to somewhere else.
    """
    escaped = BOLD_IN_TEXT_RE.sub(r"<strong>\1</strong>", escaped)
    escaped = STRIKE_IN_TEXT_RE.sub(r"<del>\1</del>", escaped)
    escaped = ITALIC_IN_TEXT_RE.sub(r"<em>\1</em>", escaped)

    def mention(match):
        username = match.group(1)
        return (
            f'<a class="mention" href="{url_for("profile", username=username)}">'
            f'@{username}</a>'
        )

    def hashtag(match):
        tag = match.group(1)
        return (
            f'<a class="hashtag" href="{url_for("tag", tag=tag.lower())}">'
            f'#{tag}</a>'
        )

    escaped = MENTION_RE.sub(mention, escaped)
    escaped = HASHTAG_RE.sub(hashtag, escaped)
    return escaped


def escaped_text(chunk, stamp, excerpt=False):
    """Escape one run of user text, resolving the tokens in it.

    Escaping happens first and covers the whole chunk, so the only markup this
    can emit is the markup it writes itself. A token it cannot resolve - a
    timestamp that will not parse, a commit log GitHub will not give us - is
    left as the text somebody typed, so the failure is visible in the post
    rather than silently swallowing the line.

    ``excerpt`` is the feed's short version of the post, which is what decides
    how much of the commit log a card shows.
    """
    escaped = html.escape(chunk)
    # **bold**, *italic*, ~~strike~~, @mentions and #tags are markup a person
    # types, so they are resolved here, after escaping and only over text that
    # is not already a link (linkify() splits those out before calling this).
    escaped = decorate_text(escaped)
    if stamp is not None:
        # The whole "[DATE] at [LOCAL USER TIME ZONE]" phrase as one unit first:
        # the "at" between the two tokens is part of that phrase, so replacing
        # them separately would leave the word stranded on its own.
        escaped = LOG_PHRASE_RE.sub(lambda _match: log_time_html(stamp), escaped)
    commits = None

    def replacement(match):
        nonlocal commits
        token = match.group(0).lower()
        if token == LOG_DATE_TOKEN:
            return log_time_html(stamp) if stamp else match.group(0)
        if token == LOG_COMMITS_TOKEN:
            if commits is None:
                commits = commit_log_html(
                    COMMIT_LOG_EXCERPT_LIMIT if excerpt else None
                )
            return commits or match.group(0)
        # A bare zone token prints nothing at all (see the note above
        # LOG_PHRASE_RE): it used to print the reader's zone, and a post written
        # while it did must not start showing raw brackets.
        return ""

    return LOG_TOKEN_RE.sub(replacement, escaped)


def linkify(value, limit=None, created_at=None):
    """Escape plain text and turn the links in it into anchors.

    Registered as the Jinja filter ``linkify``, so the returned ``Markup`` is
    safe to render: the escaping happens here, over every piece of the string,
    before any of it is marked up. Two spellings become a link - a bare URL, and
    ``[link text](https://example.com)``, where only the text is shown. A label
    is user text like any other, so it is escaped before it goes inside the
    anchor, and the address is only ever used as the ``href``.

    ``limit`` renders an excerpt, which is what the feed shows (see the Jinja
    filter's callers). A bare URL that runs to the edge of the excerpt is left as
    plain text rather than linked, since half a URL is a broken link, and a
    bracket link cut in the middle keeps its label and loses its address.

    ``created_at`` is the timestamp of the post being rendered, and passing it is
    what resolves the update-log placeholders. The substitution runs on the plain
    runs of text only, so a token inside a URL stays part of that URL instead of
    being rewritten inside the link it is building.
    """
    text = value or ""
    stamp = log_stamp(created_at)
    excerpt = limit is not None
    cut = excerpt and len(text) > limit
    if cut:
        text = MD_LINK_TAIL_RE.sub(r"\1", text[:limit])
    parts = []
    position = 0
    for match in LINK_IN_TEXT_RE.finditer(text):
        label, marked_url, bare_url = match.group(1, 2, 3)
        if marked_url is not None:
            # [link text](url): the parentheses belong to the Markdown, so the
            # address is exactly what is between them.
            url, trailing = marked_url, ""
            inner = escaped_text(label, stamp, excerpt)
        else:
            url = bare_url.rstrip(LINK_TRAILING_PUNCTUATION)
            trailing = bare_url[len(url):]
            inner = html.escape(url)
            if cut and match.end() == len(text):
                # A bare URL has no closing delimiter, so one that reaches the
                # cut may well continue past it: half a URL is not a link, and
                # it is left as the text somebody wrote.
                parts.append(escaped_text(text[position:], stamp, excerpt))
                return Markup("".join(parts))
        if len(url) < 8:  # "http://" with nothing after it is not a link
            continue
        href = url if url[:4].lower() == "http" else "https://" + url
        parts.append(escaped_text(text[position:match.start()], stamp, excerpt))
        parts.append(
            '<a class="auto-link" href="{0}" target="_blank"'
            ' rel="noopener noreferrer nofollow">{1}</a>{2}'.format(
                html.escape(href, quote=True),
                inner,
                html.escape(trailing),
            )
        )
        position = match.end()
    parts.append(escaped_text(text[position:], stamp, excerpt))
    return Markup("".join(parts))


app.jinja_env.filters["linkify"] = linkify


# The commit log -------------------------------------------------------------
# What [COMMITS] renders. The list is cached in D1 (migration 0011) and re-read
# from GitHub at most once per COMMIT_LOG_TTL_SECONDS - see the constants above
# for why that interval exists.


def commit_repo():
    """``owner/name`` of the repository the update log reads."""
    configured = None
    try:
        configured = getattr(env(), "COMMIT_LOG_REPO", None)
    except Exception:  # no request context (for example at import time)
        pass
    value = configured or os.environ.get("COMMIT_LOG_REPO") or COMMIT_LOG_REPO
    return str(value).strip()


def is_commit_sha(sha):
    """Whether a value is a commit id rather than arbitrary stored text."""
    return bool(COMMIT_SHA_RE.fullmatch(str(sha or "")))


def commit_url(sha):
    """The GitHub page for one commit, or "" when that is not a commit id."""
    if not is_commit_sha(sha):
        return ""
    return f"https://github.com/{commit_repo()}/commit/{sha}"


def commit_timestamp(value):
    """GitHub's ISO instant as the database's own UTC format, or None."""
    stamp = str(value or "").replace("T", " ").split(".")[0].rstrip("Z")
    when = db_time(stamp)
    return when.strftime(DB_TIME_FORMAT) if when else None


def lookup_commits():
    """The repository's newest commits from GitHub, or None on any failure.

    The unauthenticated API is enough for a public repository, so no token has
    to live on the Worker. It is rate-limited per IP address, which is what the
    refresh interval is for: a refusal is logged and the cached list is kept.
    """
    repo = commit_repo()
    if not repo:
        return None
    url = f"https://api.github.com/repos/{repo}/commits?per_page={COMMIT_LOG_LIMIT}"
    init = {
        "headers": {
            "accept": "application/vnd.github+json",
            "user-agent": LINK_PREVIEW_USER_AGENT,
            "x-github-api-version": "2022-11-28",
        },
        "redirect": "follow",
    }
    signal = abort_signal(COMMIT_LOG_TIMEOUT_SECONDS)
    if signal is not None:
        init["signal"] = signal
    try:
        response = run_sync(http_fetch()(url, to_js(init)))
        status = int(response.status)
        if status != 200:
            app.logger.warning("Commit log: GitHub answered %s for %s", status, repo)
            return None
        payload = json.loads(run_sync(response.text()))
    except Exception as exc:  # offline, timeout, TLS, a body that is not JSON
        app.logger.warning("Commit log failed for %s: %s", repo, exc)
        return None
    if not isinstance(payload, list):
        return None
    commits = []
    for item in payload[:COMMIT_LOG_LIMIT]:
        if not isinstance(item, dict) or not is_commit_sha(item.get("sha")):
            continue
        commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
        author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
        committed_at = commit_timestamp(author.get("date"))
        if committed_at is None:
            continue
        lines = str(commit.get("message") or "").splitlines()
        commits.append({
            "sha": str(item["sha"]),
            # The subject line only: a commit body belongs in the commit, not in
            # a one-line log.
            "message": clean_text(lines[0] if lines else "", COMMIT_LOG_MESSAGE_LIMIT),
            "committed_at": committed_at,
        })
    return commits


def commit_sync_state():
    """``(seconds since the last attempt, whether it worked)``, or (None, False)."""
    row = first("SELECT attempted_at, succeeded FROM commit_sync WHERE id=1")
    if not row:
        return None, False
    when = db_time(row["attempted_at"])
    if when is None:
        return None, bool(row["succeeded"])
    return (utcnow() - when).total_seconds(), bool(row["succeeded"])


def refresh_commit_log(force=False):
    """Re-read the commits from GitHub, unless the last attempt was recent.

    The attempt is recorded *before* the request goes out, so the failure path
    is throttled too: an unreachable or rate-limited GitHub is asked again after
    COMMIT_LOG_RETRY_SECONDS instead of on every page render.
    """
    age, succeeded = commit_sync_state()
    if not force and age is not None and age < (
        COMMIT_LOG_TTL_SECONDS if succeeded else COMMIT_LOG_RETRY_SECONDS
    ):
        return
    execute(
        "INSERT INTO commit_sync (id, attempted_at, succeeded)"
        " VALUES (1, datetime('now'), 0)"
        " ON CONFLICT(id) DO UPDATE SET attempted_at=datetime('now'), succeeded=0",
    )
    commits = lookup_commits()
    if commits is None:
        return
    # The list is whatever GitHub just showed us, so a rewritten or removed
    # commit cannot linger in the log.
    execute("DELETE FROM commit_log")
    for item in commits:
        execute(
            "INSERT INTO commit_log (sha, message, committed_at) VALUES (?, ?, ?)",
            item["sha"], item["message"], item["committed_at"],
        )
    execute("UPDATE commit_sync SET succeeded=1 WHERE id=1")


def commit_log_html(limit=None):
    """The [COMMITS] token's markup: one line per commit, newest first.

    Each line is plain text - the commit's own time, then its subject. Nothing is
    linked: the log is a line of the post, and turning every entry into a blue
    anchor made an update log read as a list of links rather than a list of
    changes. A commit message is still somebody else's text, so it is escaped
    like any other user text.

    Returns "" when there is nothing to show, so the caller can leave the token
    as the text somebody typed instead of rendering an empty list.
    """
    try:
        refresh_commit_log()
        rows = query(
            "SELECT sha, message, committed_at FROM commit_log"
            " ORDER BY committed_at DESC, sha DESC LIMIT ?",
            COMMIT_LOG_LIMIT if limit is None else limit,
        )
    except Exception as exc:  # most likely: migration 0011 is not applied yet
        app.logger.warning("Commit log unavailable: %s", exc)
        return ""
    lines = []
    for row in rows:
        # A row that is not a commit id is not a commit we fetched, so it is
        # dropped rather than printed.
        if not is_commit_sha(row["sha"]):
            continue
        stamp = log_stamp(row["committed_at"])
        when = log_time_html(stamp) if stamp else str(row["committed_at"])
        lines.append(
            f'<li>{when} {html.escape(str(row["message"] or ""))}</li>'
        )
    if not lines:
        return ""
    return f'<ul class="commit-log">{"".join(lines)}</ul>'


def human_filesize(value):
    """Bytes as a short human string, for the owner's storage line."""
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


app.jinja_env.filters["filesize"] = human_filesize
app.jinja_env.filters["name_initial"] = name_initial
# The inbox list shows one line of a body rather than the whole notice.
app.jinja_env.filters["message_preview"] = message_preview
# The admin panel and the owner panel both render ban badges, and the ban rules
# live in one place, so the templates ask these instead of re-deriving anything.
app.jinja_env.globals["ban_state"] = ban_state
app.jinja_env.globals["active_bans"] = active_bans
app.jinja_env.globals["ban_message"] = ban_message
app.jinja_env.globals["is_owner_username"] = is_owner_username
# Every post link is built from the post row, so the Google+ URL shape lives in
# one place (canonical_post_path) instead of being spelled out in each template.
app.jinja_env.globals["post_url"] = canonical_post_path
app.jinja_env.globals["BAN_CHOICES"] = BAN_CHOICES
app.jinja_env.globals["BAN_DURATIONS"] = BAN_DURATIONS
app.jinja_env.globals["DEFAULT_BAN_DURATION"] = DEFAULT_BAN_DURATION
app.jinja_env.globals["DELETED_ACCOUNT_NAME"] = DELETED_ACCOUNT_NAME
# The thread composer and its error message
# Templates word the same limits the routes enforce, so a box and its error
# message cannot drift apart.
app.jinja_env.globals["MAX_DM_LENGTH"] = MAX_DM_LENGTH
app.jinja_env.globals["MESSAGE_PREVIEW_LENGTH"] = MESSAGE_PREVIEW_LENGTH
app.jinja_env.globals["MODERATION_USERNAME_DEFAULT"] = MODERATION_USERNAME_DEFAULT
app.jinja_env.globals["is_moderation_account"] = is_moderation_account


def http_fetch():
    """The JS ``fetch`` this Worker runs on, looked up per call.

    Not ``workers.fetch``: that wrapper takes options as keyword arguments and
    rejects the standard ``fetch(url, init)`` call. The JS global is the same
    function underneath, and taking it here rather than at import time keeps JS
    proxies out of module globals (see the note at the top of this file).
    """
    from js import fetch as worker_fetch
    return worker_fetch


def abort_signal(seconds):
    """A JS AbortSignal that fires after ``seconds``, or None if unavailable."""
    try:
        from js import AbortSignal
        return AbortSignal.timeout(int(seconds * 1000))
    except Exception:  # pragma: no cover - depends on the runtime
        return None


def is_public_url(url):
    """True for http(s) URLs that point at somebody else's public server.

    Guards the outbound fetch against being aimed at loopback, private ranges or
    bare intranet hostnames (which a Worker cannot reach anyway, but there is no
    reason to try).
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return False
    if host.endswith((".local", ".internal", ".localhost", ".home.arpa")):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True  # an ordinary hostname
    return not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_reserved or address.is_multicast or address.is_unspecified
    )


def extract_post_link(content, own_host=""):
    """The first link in a post body that is worth turning into a card."""
    for match in URL_IN_TEXT_RE.finditer(content or ""):
        candidate = match.group(0).rstrip(".,;:!?)")
        if not is_public_url(candidate):
            continue
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        if own_host and host == own_host.lower():
            continue  # a link back to this site: no card needed
        if parts.path.lower().endswith(LINK_PREVIEW_SKIP_EXTENSIONS):
            continue
        return candidate
    return ""


def parse_meta_tags(page):
    """Map a page's meta tags to their content, keyed by property/name."""
    found = {}
    for tag in META_TAG_RE.findall(page):
        attributes = {}
        for match in ATTR_RE.finditer(tag):
            value = next(
                group for group in match.groups()[1:] if group is not None
            )
            attributes.setdefault(match.group(1).lower(), value)
        key = (attributes.get("property") or attributes.get("name") or "").lower()
        if key and attributes.get("content") is not None:
            found.setdefault(key, attributes["content"])
    return found


def clean_text(value, limit):
    """Unescape, collapse and trim a value pulled out of a page's HTML."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", html.unescape(value)).strip()[:limit].strip()


def absolute_image_url(value, base_url):
    """Resolve a card image to an http(s) URL we are willing to hotlink."""
    if not value:
        return ""
    value = html.unescape(value).strip()
    if value.startswith("//"):
        value = "https:" + value
    elif value.startswith("/"):
        value = urljoin(base_url or "", value)
    if not value.lower().startswith(("http://", "https://")) or len(value) > 1000:
        return ""
    return value if is_public_url(value) else ""


def site_label(url):
    """The bare domain shown at the foot of a card, e.g. ``mediafire.com``."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def parse_link_preview(page, base_url=""):
    """Build a card from a page's Open Graph tags, falling back to <title>.

    Returns None when the page offers nothing worth showing, so the caller can
    record a miss instead of caching an empty card.
    """
    meta = parse_meta_tags(page)
    title = clean_text(
        meta.get("og:title") or meta.get("twitter:title"), LINK_PREVIEW_TITLE_LIMIT
    )
    if not title:
        match = TITLE_TAG_RE.search(page)
        title = clean_text(match.group(1) if match else "", LINK_PREVIEW_TITLE_LIMIT)
    image = absolute_image_url(
        meta.get("og:image")
        or meta.get("og:image:secure_url")
        or meta.get("twitter:image"),
        base_url,
    )
    description = clean_text(
        meta.get("og:description")
        or meta.get("twitter:description")
        or meta.get("description"),
        LINK_PREVIEW_DESCRIPTION_LIMIT,
    )
    if description and description == title:
        description = ""
    # A card needs a title or an image to say anything the post's own text does not;
    # pages offering neither just keep the plain link.
    if not (title or image):
        return None
    return {
        "title": title or None,
        "description": description or None,
        "image": image or None,
        "site": site_label(base_url) or None,
    }


def lookup_link_preview(url):
    """Fetch ``url`` and read its card out of the HTML, or None on any failure."""
    if not is_public_url(url):
        return None
    init = {
        "headers": {
            "accept": "text/html,application/xhtml+xml",
            "user-agent": LINK_PREVIEW_USER_AGENT,
        },
        "redirect": "follow",
    }
    signal = abort_signal(LINK_PREVIEW_TIMEOUT_SECONDS)
    if signal is not None:
        init["signal"] = signal
    try:
        response = run_sync(http_fetch()(url, to_js(init)))
        status = int(response.status)
        headers = response.headers
        content_type = (headers.get("content-type") or "").lower()
        if status >= 400 or "html" not in content_type:
            return None
        declared = (headers.get("content-length") or "").strip()
        if declared.isdigit() and int(declared) > LINK_PREVIEW_MAX_CHARS * 8:
            return None
        page = run_sync(response.text())[:LINK_PREVIEW_MAX_CHARS]
        final_url = response.url or url
    except Exception as exc:  # offline, DNS failure, timeout, TLS, bad HTML...
        app.logger.warning("Link preview failed for %s: %s", url, exc)
        return None
    return parse_link_preview(page, final_url)


def preview_age_seconds(value):
    """Seconds since a stored ``fetched_at``, or None when unparseable."""
    try:
        stored = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None
    return (datetime.now(timezone.utc).replace(tzinfo=None) - stored).total_seconds()


def stored_link_preview(url):
    """The cached card for ``url`` while it is still fresh, else None."""
    row = first("SELECT * FROM link_previews WHERE url=?", url)
    if not row:
        return None
    age = preview_age_seconds(row["fetched_at"])
    if age is None:
        return None
    worked = bool(row["title"] or row["image"])
    return row if age < (
        LINK_PREVIEW_TTL_SECONDS if worked else LINK_PREVIEW_RETRY_SECONDS
    ) else None


def store_link_preview(url, preview):
    """Cache a card (or the fact that there isn't one) for ``url``."""
    preview = preview or {}
    execute(
        """INSERT INTO link_previews (url, title, description, image, site, fetched_at)
           VALUES (?, ?, ?, ?, ?, datetime('now'))
           ON CONFLICT(url) DO UPDATE SET title=excluded.title,
                                         description=excluded.description,
                                         image=excluded.image,
                                         site=excluded.site,
                                         fetched_at=excluded.fetched_at""",
        url,
        preview.get("title"),
        preview.get("description"),
        preview.get("image"),
        preview.get("site") or site_label(url),
    )


def ensure_link_preview(url, force=False):
    """Return a card for ``url``, fetching it only when the cache has no fresh one."""
    if not url:
        return None
    if not force:
        cached = stored_link_preview(url)
        if cached is not None:
            return cached
    preview = lookup_link_preview(url)
    store_link_preview(url, preview)
    return preview


def save_image_upload(file):
    """Store an uploaded image in D1.

    Returns (filename, None) when the file was stored, (None, None) when the
    form carried no file at all, and (None, message) when we have to refuse it
    — so the caller can tell the user instead of silently dropping the upload.
    """
    if not file or not file.filename:
        return None, None
    original = secure_filename(file.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return None, "That file is not a supported image. Use PNG, JPG, GIF, or WebP."
    data = file.read()
    if not data:
        return None, "That file was empty. Pick an image and try again."
    if len(data) > MAX_IMAGE_BYTES:
        return None, f"Images must be {MAX_IMAGE_BYTES // 1000} KB or smaller."
    filename = secrets.token_hex(16) + "." + ext
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    try:
        # Hand the raw bytes to D1 - do NOT wrap them in to_js() first. A
        # converted value arrives as a typed array, and the Workers RPC layer
        # then walks it element by element to check it can be sent, which cost
        # ~2 s of CPU for a 600 KB image. That blew the runtime's CPU budget and
        # made any upload above roughly 100 KB fail with Cloudflare Error 1101
        # ("Worker threw exception") or 1102, straight past the flash message.
        # Plain Python bytes are not walked, and D1 stores them as a BLOB.
        execute(
            "INSERT INTO uploads (filename, content_type, size, data) VALUES (?, ?, ?, ?)",
            filename, content_type, len(data), data,
        )
    except Exception as exc:
        # Storing the image is best-effort: never let it take the whole request
        # down with a runtime error page when we can say what happened instead.
        app.logger.warning("Could not store upload %s (%d bytes): %s", filename, len(data), exc)
        return None, (
            "That image was too big for the site to process. Try one under "
            f"{MAX_IMAGE_BYTES // 1000} KB."
        )
    return filename, None


def delete_upload(filename):
    """Best-effort cleanup of a stored image we are replacing or clearing."""
    if not filename:
        return
    try:
        execute("DELETE FROM uploads WHERE filename=?", filename)
    except Exception as exc:  # never let cleanup break a profile save
        app.logger.warning("Could not delete upload %s: %s", filename, exc)


@app.route("/uploads/<filename>")
def uploads(filename):
    if "/" in filename or "\\" in filename or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9]+", filename):
        abort(404)
    row = first("SELECT content_type, data FROM uploads WHERE filename=?", filename)
    if row is None:
        abort(404)
    mime = row["content_type"] or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(
        blob_to_bytes(row["data"]),
        status=200,
        content_type=mime,
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.route("/static/<path:path>")
def static_files(path):
    """Proxy Workers static assets (./public) through the Flask app."""
    response = run_sync(env().ASSETS.fetch(f"https://assets.local/static/{path}"))
    headers = response.headers
    mime = headers.get("content-type") or mimetypes.guess_type(path)[0] or "text/plain"
    return Response(
        read_body_bytes(response),
        status=int(response.status),
        content_type=mime,
        headers={"Cache-Control": headers.get("cache-control") or "public, max-age=3600"},
    )


@app.route("/")
def home():
    """The stream.

    ``?category=`` keeps the two feeds apart, ``?feed=following`` is the people
    you follow, ``?feed=incoming`` the people who follow you (Google+'s
    "Incoming"), and ``?feed=circle&circle=<id>`` one of your circles. A signed-in
    visitor sees their own drafts nowhere - drafts are opened by URL - but does
    see circle posts addressed to a circle they are in.
    """
    feed = request.args.get("feed", "")
    category = request.args.get("category", "")
    if category not in POST_CATEGORIES:
        category = ""
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    clause, params = visibility_sql(viewer_id)
    where = "WHERE " + clause
    active_circle = None
    if feed == "following":
        # The Following stream and the per-category tabs are alternatives, not
        # combinable filters - Google+ had one stream per circle, not a grid.
        category = ""
        if not viewer_id:
            flash("Sign in to see posts from the people you follow.", "error")
            return redirect(url_for("login", next=url_for("home", feed="following")))
        # Your own posts belong in your stream too, the way they did on Google+.
        where += (
            " AND posts.user_id IN (SELECT followed_id FROM follows"
            " WHERE follower_id=? UNION SELECT ?)"
        )
        params.extend([viewer_id, viewer_id])
    elif feed == "incoming":
        category = ""
        if not viewer_id:
            flash("Sign in to see the people who follow you.", "error")
            return redirect(url_for("login", next=url_for("home", feed="incoming")))
        # Incoming: their posts, from accounts that follow you and that you do
        # not follow back. G+'s cheapest way to notice a new account.
        where += (
            " AND posts.user_id IN (SELECT follower_id FROM follows WHERE followed_id=?)"
            " AND posts.user_id NOT IN (SELECT followed_id FROM follows WHERE follower_id=?)"
        )
        params.extend([viewer_id, viewer_id])
    elif feed == "circle":
        category = ""
        circle_arg = request.args.get("circle", "")
        active_circle = circle_by_id(circle_arg) if circle_arg.isdigit() else None
        if not viewer_id or not active_circle or active_circle["user_id"] != viewer_id:
            flash("That circle is not one of yours.", "error")
            return redirect(url_for("home"))
        where += (
            " AND posts.user_id IN (SELECT user_id FROM circle_members"
            " WHERE circle_id=?)"
        )
        params.append(active_circle["id"])
    else:
        feed = ""
        if category:
            where += " AND posts.category=?"
            params.append(category)

    # Infinite scroll / "Older posts": the cursor is the id of the last post on
    # the page, so a new post arriving mid-scroll cannot make the reader see one
    # twice or skip one.
    before = request.args.get("before", "")
    if before.isdigit():
        where += " AND posts.id < ?"
        params.append(int(before))
    rows = fetch_posts(where, tuple(params), limit=FEED_PAGE_SIZE + 1,
                       order="posts.id DESC")
    has_more = len(rows) > FEED_PAGE_SIZE
    posts = rows[:FEED_PAGE_SIZE]
    next_before = posts[-1]["id"] if has_more and posts else None
    next_url = None
    if has_more and next_before:
        args = {"before": next_before}
        if category:
            args["category"] = category
        if feed:
            args["feed"] = feed
        if active_circle:
            args["circle"] = active_circle["id"]
        next_url = url_for("home", **args)
    return render_template(
        "index.html",
        posts=posts,
        category=category,
        feed=feed,
        active_circle=active_circle,
        my_circles=circle_rows(viewer_id),
        has_more=has_more,
        next_before=next_before,
        next_url=next_url,
        tags=top_tags(),
        # How many people you follow, shown on the Following tab.
        following_total=follow_counts(viewer["id"])[1] if viewer else 0,
        category_labels=POST_CATEGORY_LABELS,
        counts=category_counts(viewer_id),
    )


@app.route("/<author_id>/posts/<public_id>", methods=["GET", "POST"])
def post_with_author(author_id, public_id):
    """A post at its own URL: ``/<account number>/posts/<post id>``.

    This is the canonical shape. The post is found by its own id, so the leading
    number is not what identifies it: a read carrying the wrong one is sent to
    the right address rather than served a second time. A POST is handled in
    place instead of being redirected away from, so a comment typed into a page
    opened before the correction is still saved.
    """
    rows = fetch_posts("WHERE posts.public_id=?", (public_id,))
    if not rows:
        abort(404)
    item = rows[0]
    if request.method == "GET":
        if not may_view(item):
            abort(404)
        canonical = canonical_post_path(item)
        if request.path != canonical:
            return redirect(canonical, 301)
    return render_post_page(item)


@app.route("/posts/<public_id>", methods=["GET", "POST"])
def post(public_id):
    """A post addressed without its author: ``/posts/<post id>``.

    Links handed out between migrations 0012 and 0013 had this shape, so they
    keep working. Every real post has an author, so a read is sent on to the full
    address; a POST is handled in place so a comment is not lost. A post with no
    author at all (the seeded welcome post) lives here.
    """
    rows = fetch_posts("WHERE posts.public_id=?", (public_id,))
    if not rows:
        abort(404)
    item = rows[0]
    if request.method == "GET":
        if not may_view(item):
            abort(404)
        canonical = canonical_post_path(item)
        if request.path != canonical:
            return redirect(canonical, 301)
    return render_post_page(item)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post_legacy(post_id):
    """The original URL shape (``/post/29``).

    Links already shared and pages already open keep working: a read is
    redirected to the post's own URL, and a comment submitted from an old copy of
    the page is still saved before the redirect.
    """
    rows = fetch_posts("WHERE posts.id=?", (post_id,))
    if not rows:
        abort(404)
    item = rows[0]
    if request.method == "GET":
        if not may_view(item):
            abort(404)
        return redirect(canonical_post_path(item), 301)
    return render_post_page(item)


def render_post_page(item):
    """The post page itself: the draft gate, the comment form and the render."""
    canonical = canonical_post_path(item)
    if not may_view(item):
        abort(404)
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0

    if request.method == "POST":
        # The account row itself, not the session id: this route writes a comment
        # keyed to that id, so a cookie left over from a database that no longer
        # has the row would fail the foreign key instead of the sign-in check.
        commenter = current_user()
        if not commenter:
            flash("Log in or create an account to comment.", "error")
            return redirect(url_for("login", next=canonical + "#comments"))
        comment_ban = active_bans(commenter).get("comment")
        if comment_ban:
            # Reading the thread is still allowed; only writing to it is not.
            flash(ban_message("comment", comment_ban), "error")
            return redirect(canonical + "#comments")
        content = request.form.get("content", "").strip()
        parent_id = request.form.get("parent_id", "").strip()
        # Replies are one level deep: a reply to a reply attaches to the same parent,
        # which keeps the thread readable without unbounded nesting.
        parent = None
        if parent_id.isdigit():
            parent = first(
                "SELECT id, parent_id FROM comments WHERE id=? AND post_id=?",
                int(parent_id), item["id"],
            )
            if parent and parent["parent_id"]:
                parent = first("SELECT id FROM comments WHERE id=?", parent["parent_id"])
        anchor = f"#comment-{parent['id']}" if parent else "#comments"
        if not content:
            flash("Please enter a comment.", "error")
        elif len(content) > 2000:
            flash("Your comment is too long.", "error")
        elif item.get("locked"):
            flash("The author has locked this post. No new comments can be added.", "error")
        else:
            execute(
                "INSERT INTO comments (post_id, user_id, content, parent_id) VALUES (?, ?, ?, ?)",
                item["id"], commenter["id"], content, parent["id"] if parent else None,
            )
            created = first("SELECT last_insert_rowid() AS id")
            new_id = created["id"] if created else None
            # Tell the people the comment is about: the post's author for a new
            # comment, the comment's author for a reply. A reply to your own
            # comment notifies nobody (notify() drops self-actions).
            if item.get("user_id"):
                notify(
                    item["user_id"], "reply" if parent else "comment",
                    commenter["id"], item["id"], new_id,
                )
            if parent:
                parent_row = first("SELECT user_id FROM comments WHERE id=?", parent["id"])
                if parent_row:
                    notify(parent_row["user_id"], "reply", commenter["id"],
                           item["id"], new_id)
            notify_mentions(content, commenter, item["id"], new_id)
            return redirect(canonical + anchor)

    return render_template(
        "post.html",
        post=item,
        comments=comment_threads(item["id"], viewer_id),
        can_manage=can_manage_post(item),
        viewer_id=viewer_id,
        images=post_image_rows(item["id"]),
        people=post_people_rows(item["id"]),
        embed=embed_for(item.get("link_url")),
        shares=shares_of(item["id"]),
        voters=voters_of(item["id"], 1),
        share_target=(
            fetch_posts("WHERE posts.id=?", (item["share_of"],))[0]
            if item.get("share_of") and gplus_schema() else None
        ),
        audience_name=audience_label({**item, "circle_name":
                                      (circle_for_post(item) or {}).get("name")}),
        my_circle=circle_of_author_for(viewer_id, item.get("user_id")),
        albums=albums_for(item.get("user_id"), viewer_id),
        post_albums={row["id"] for row in post_album_rows(item["id"])},
        embed_url=url_for("embed_post", post_id=item["id"], _external=True),
    )


@app.post("/post/<int:post_id>/vote")
def vote_post(post_id):
    """Like (+1) or dislike (-1) a post; repeating the same vote clears it."""
    item = first(
        "SELECT id, user_id FROM posts WHERE id=? AND status='published'", post_id
    )
    if not item:
        abort(404)
    # The account row rather than the session id, for the same reason a comment
    # is written with it: this inserts a row keyed to that id.
    voter = current_user()
    if not voter:
        flash("Sign in to like or dislike posts.", "error")
        return redirect(url_for("login", next=post_path(post_id)))
    try:
        value = int(request.form.get("value", "0"))
    except ValueError:
        value = 0
    if value not in (-1, 1):
        value = 0
    user_id = voter["id"]
    existing = first(
        "SELECT value FROM post_votes WHERE post_id=? AND user_id=?", post_id, user_id
    )
    if value == 0 or (existing and existing["value"] == value):
        execute("DELETE FROM post_votes WHERE post_id=? AND user_id=?", post_id, user_id)
    else:
        execute(
            """INSERT INTO post_votes (post_id, user_id, value) VALUES (?, ?, ?)
               ON CONFLICT(post_id, user_id) DO UPDATE SET value=excluded.value""",
            post_id, user_id, value,
        )
        # Only a +1 rings the bell; a downvote was G+'s "dislike" and stayed
        # private to the person who cast it.
        if value == 1:
            notify(item["user_id"], "like", user_id, post_id)
    return redirect(request.referrer or post_path(post_id))


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_post():
    """Any signed-in account can post; the category follows from the account."""
    user = current_user()
    if request.method == "POST":
        if posting_blocked():
            return redirect(url_for("home"))
        target = save_post()
        if target:
            if request.form.get("status") == "draft":
                flash("Draft saved - it stays hidden until you publish it.", "success")
            else:
                flash("Post published.", "success")
            return redirect(target)
    return render_template(
        "post_editor.html",
        post=None,
        cancel_url=url_for("home"),
        can_choose_status=is_admin(),
        can_choose_category=is_admin(),
        default_category=post_category_for(user["username"]),
        circles=circle_rows(user["id"]),
        collections=collection_rows(user["id"], user["id"]),
        my_communities=communities_for(user["id"]),
        my_events=safe_query(
            "SELECT * FROM events WHERE owner_id=? ORDER BY starts_at", user["id"]
        ),
        my_pages=pages_for(user["id"]),
        max_images=MAX_POST_IMAGES,
        images=[],
        tagged_value="",
        audience_labels=AUDIENCE_LABELS,
    )


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    # Read through fetch_posts so the row carries its author's public id: the
    # editor shows the post's own URL, which needs both halves of it.
    rows = fetch_posts("WHERE posts.id=?", (post_id,))
    if not rows:
        abort(404)
    item = rows[0]
    if not can_manage_post(item):
        flash("You can only edit your own posts.", "error")
        return redirect(post_path(post_id))
    if request.method == "POST":
        if posting_blocked():
            return redirect(post_path(post_id))
        target = save_post(item)
        if target:
            flash("Post updated.", "success")
            return redirect(target)
    images = post_image_rows(item["id"])
    return render_template(
        "post_editor.html",
        post=item,
        cancel_url=post_path(post_id),
        can_choose_status=is_admin(),
        can_choose_category=is_admin(),
        default_category=item["category"],
        circles=circle_rows(current_user()["id"]),
        collections=collection_rows(current_user()["id"], current_user()["id"]),
        my_communities=communities_for(current_user()["id"]),
        my_events=safe_query(
            "SELECT * FROM events WHERE owner_id=? ORDER BY starts_at",
            current_user()["id"],
        ),
        my_pages=pages_for(current_user()["id"]),
        max_images=MAX_POST_IMAGES,
        images=images,
        tagged_value=" ".join("@" + person["username"]
                              for person in post_people_rows(item["id"])),
        audience_labels=AUDIENCE_LABELS,
    )


@app.post("/post/<int:post_id>/delete")
@login_required
def delete_post(post_id):
    item = first("SELECT * FROM posts WHERE id=?", post_id)
    if not item:
        abort(404)
    if not can_manage_post(item):
        flash("You can only delete your own posts.", "error")
        return redirect(post_path(post_id))
    # Take the pictures and the revival-only rows with the post: `uploads` holds
    # the bytes, and nothing else will ever reference them again.
    for image in post_image_rows(post_id):
        delete_upload(image["filename"])
    if gplus_schema():
        for table, column in (
            ("post_images", "post_id"), ("post_tags", "post_id"),
            ("post_people", "post_id"), ("shares", "post_id"),
            ("post_mutes", "post_id"), ("notifications", "post_id"),
        ):
            safe_execute(f"DELETE FROM {table} WHERE {column}=?", post_id)
        safe_execute(
            "DELETE FROM comment_votes WHERE comment_id IN"
            " (SELECT id FROM comments WHERE post_id=?)", post_id,
        )
        safe_execute("DELETE FROM shares WHERE post_id_created=?", post_id)
    execute("DELETE FROM post_votes WHERE post_id=?", post_id)
    execute("DELETE FROM comments WHERE post_id=?", post_id)
    execute("DELETE FROM posts WHERE id=?", post_id)
    flash("Post deleted.", "success")
    return redirect(url_for("admin") if is_admin() else url_for("home"))


def tagged_people(value, author_id):
    """Accounts named in the editor's "tag people" box, by handle."""
    found = []
    seen = {author_id}
    for raw in re.split(r"[,\s]+", value or ""):
        name = raw.strip().lstrip("@")
        if not name or len(found) >= MAX_PEOPLE_TAGGED:
            continue
        row = first(
            "SELECT id, username FROM users WHERE username=? COLLATE NOCASE", name
        )
        if row and row["id"] not in seen:
            seen.add(row["id"])
            found.append(row)
    return found


def post_audience_from_form(user):
    """Validate the editor's audience, returning (audience, circle, error)."""
    audience = request.form.get("audience", "public")
    if audience not in POST_AUDIENCES or not gplus_schema():
        return "public", None, None
    circle = None
    if audience == "circles":
        circle_id = request.form.get("circle_id", "")
        circle = circle_by_id(circle_id) if circle_id.isdigit() else None
        if not circle or circle["user_id"] != user["id"]:
            return audience, None, "Pick one of your own circles to share with."
    return audience, circle, None


def save_post(item=None):
    """Create or update a post from the editor form; returns where to go next.

    Everything migration 0016 added is validated here rather than trusted: a
    circle, collection, community, event and set of tagged people all have to
    belong to the person posting, because the ids arrive in a form.
    """
    user = current_user()
    # Posting as a Page (migration 0017). The account stays the author of record
    # for moderation and for the post's own URL; the page is what readers see.
    page = None
    page_id = request.form.get("page_id", "")
    if page_id.isdigit() and gplus2_schema():
        page = page_by_id(int(page_id))
        if not can_manage_page(page, user):
            flash("Pick a page you manage, or post as yourself.", "error")
            return None
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    if not title or not content:
        flash("Title and content are required.", "error")
        return None
    if len(title) > MAX_POST_TITLE:
        flash(f"Titles must be {MAX_POST_TITLE} characters or fewer.", "error")
        return None
    status = request.form.get("status", "published")
    if status not in POST_STATUSES or not is_admin():
        status = "published"  # drafts stay a site-owner tool
    category = post_category_for(user["username"])
    if is_admin() and request.form.get("category") in POST_CATEGORIES:
        category = request.form["category"]

    audience, circle, audience_error = post_audience_from_form(user)
    if audience_error:
        flash(audience_error, "error")
        return None
    collection = None
    collection_id = request.form.get("collection_id", "")
    if collection_id.isdigit() and gplus_schema():
        collection = collection_by_id(collection_id)
        if collection and collection["user_id"] != user["id"]:
            collection = None
    community = None
    community_id = request.form.get("community_id", "")
    if community_id.isdigit() and gplus_schema():
        community = safe_first("SELECT * FROM communities WHERE id=?", int(community_id))
        if community:
            member = community_membership(community["id"], user["id"])
            if not member and community["owner_id"] != user["id"]:
                flash("Join that community before posting in it.", "error")
                return None
    event = None
    event_id = request.form.get("event_id", "")
    if event_id.isdigit() and gplus_schema():
        event = event_by_id(int(event_id))
        if event and event["owner_id"] != user["id"]:
            event = None
    warning = (request.form.get("content_warning", "") or "").strip()[:120]
    tagged = tagged_people(request.form.get("tag_people", ""), user["id"])

    # Photos are saved before the post so a refused upload cannot leave a post
    # behind that the person has to delete. Existing images count toward the cap
    # when editing; anything over it is refused rather than silently dropped.
    existing_images = post_image_rows(item["id"]) if item and gplus_schema() else []
    removals = {value for value in request.form.getlist("remove_image") if value.isdigit()}
    kept = [image for image in existing_images if str(image["id"]) not in removals]
    new_files = [f for f in request.files.getlist("images") if f and f.filename]
    if len(kept) + len(new_files) > MAX_POST_IMAGES:
        flash(f"A post can hold {MAX_POST_IMAGES} pictures.", "error")
        return None
    saved_uploads = []
    for file in new_files:
        filename, error = save_image_upload(file)
        if error:
            for stored in saved_uploads:
                delete_upload(stored)
            flash(error, "error")
            return None
        if filename:
            saved_uploads.append(filename)

    # A link in the body gets a card under the post. The card is fetched right here,
    # once, and cached in D1 so no page render ever waits on another website.
    link_url = extract_post_link(content, request.host.split(":")[0])
    if link_url:
        ensure_link_preview(link_url)

    if not gplus_schema():
        # Before migration 0016 the audience columns do not exist yet. Saving the
        # old shape keeps posting (and the site) working until `npm run db:remote`
        # has been run - the profile pictures that were already accepted are put
        # back, because nothing can reference them.
        for stored in saved_uploads:
            delete_upload(stored)
        if item is None:
            execute(
                "INSERT INTO posts (title, content, status, user_id, category,"
                " link_url, public_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                title, content, status, user["id"], category, link_url or None,
                generate_post_public_id(),
            )
            created = first("SELECT last_insert_rowid() AS id")
            return post_path(created["id"]) if created else url_for("home")
        execute(
            "UPDATE posts SET title=?, content=?, status=?, category=?,"
            " link_url=? WHERE id=?",
            title, content, status, category, link_url or None, item["id"],
        )
        return post_path(item["id"])

    if item is None:
        execute(
            "INSERT INTO posts (title, content, status, user_id, category, link_url,"
            " public_id, audience, circle_id, collection_id, community_id, event_id,"
            " content_warning) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            title, content, status, user["id"], category, link_url or None,
            generate_post_public_id(), audience,
            circle["id"] if circle else None,
            collection["id"] if collection else None,
            community["id"] if community else None,
            event["id"] if event else None,
            warning or None,
        )
        created = first("SELECT last_insert_rowid() AS id")
        if not created:
            return url_for("home")
        post_id = created["id"]
    else:
        post_id = item["id"]
        execute(
            "UPDATE posts SET title=?, content=?, status=?, category=?, link_url=?,"
            " audience=?, circle_id=?, collection_id=?, community_id=?, event_id=?,"
            " content_warning=? WHERE id=?",
            title, content, status, category, link_url or None, audience,
            circle["id"] if circle else None,
            collection["id"] if collection else None,
            community["id"] if community else None,
            event["id"] if event else None,
            warning or None, post_id,
        )
        for image in existing_images:
            if str(image["id"]) in removals:
                delete_upload(image["filename"])
                execute("DELETE FROM post_images WHERE id=?", image["id"])

    if gplus_schema():
        position_row = safe_first(
            "SELECT COALESCE(MAX(position), -1) + 1 AS next FROM post_images WHERE post_id=?",
            post_id,
        )
        position = int(position_row["next"]) if position_row else 0
        for index, filename in enumerate(saved_uploads):
            safe_execute(
                "INSERT INTO post_images (post_id, filename, position) VALUES (?, ?, ?)",
                post_id, filename, position + index,
            )
        safe_execute("DELETE FROM post_people WHERE post_id=?", post_id)
        for person in tagged:
            safe_execute(
                "INSERT OR IGNORE INTO post_people (post_id, user_id) VALUES (?, ?)",
                post_id, person["id"],
            )
            notify(person["id"], "tag", user["id"], post_id)
        store_post_tags(post_id, content)
        notify_mentions(content, user, post_id)

    if gplus2_schema():
        safe_execute(
            "UPDATE posts SET page_id=? WHERE id=?",
            page["id"] if page else None, post_id,
        )

    return post_path(post_id)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not valid_username(username):
            flash("Username must be 3–24 characters and use only letters, numbers, or underscores.", "error")
        elif not 1 <= len(display_name) <= 40:
            flash("Display name must be 1–40 characters.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif first("SELECT id FROM users WHERE username=? COLLATE NOCASE", username):
            flash("That username is already taken.", "error")
        else:
            picture, picture_error = save_image_upload(request.files.get("profile_picture"))
            if picture_error:
                flash(picture_error, "error")
                return render_template("register.html")
            user = create_account(
                username, display_name, hash_password(password), picture
            )
            session.clear()
            session["user_db_id"] = user["id"]
            if is_owner_username(username):
                # The seeded welcome post stays authorless until an owner account
                # exists; the first owner to register claims it (migration 0006 does
                # the same for a database that already had the account).
                execute(
                    "UPDATE posts SET user_id=?, category='systematics' WHERE user_id IS NULL",
                    user["id"],
                )
            flash("Your account has been created!", "success")
            return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))
    next_url = request.args.get("next", "")
    remember = False
    # A session that an account ban just ended carries that account's id, so the
    # notice this page shows survives the confirmation-page round trip. On an
    # ordinary visit there is no key here and nothing is looked up.
    notice_for = session.get("notice_for")
    pending_notice = latest_ban_notice(notice_for, "account") if notice_for else None
    if request.method == "POST":
        remember = bool(request.form.get("remember"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
        if user and verify_password(user["password_hash"], password):
            # Refused here as well as in enforce_moderation(), because this is the
            # one request that hands out a session in the first place.
            ban = active_bans(user).get("account")
            if user.get("deleted_at"):
                flash("That account has been deleted.", "error")
            elif ban:
                flash(ban_message("account", ban), "error")
                # The inbox needs a session and the ban is what removed it, so the
                # notice is shown right here instead of being unreachable.
                pending_notice = latest_ban_notice(user["id"], "account")
            else:
                session.clear()
                session["user_db_id"] = user["id"]
                # "Remember me" is the only thing that gives the cookie an expiry
                # date; without it the browser drops it when it closes. session.clear()
                # above also discarded any previous choice, so this is set fresh each
                # sign-in rather than inherited from the last one.
                if request.form.get("remember"):
                    session.permanent = True
                return redirect(safe_next(request.form.get("next"), url_for("home")))
        else:
            flash("Invalid username or password.", "error")
    return render_template(
        "login.html",
        next_url=next_url,
        remember=remember,
        remember_days=REMEMBER_SESSION_DAYS,
        ban_notice=pending_notice,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# Social links ----------------------------------------------------------------
# The editor's boxes, the stored JSON and the profile's chips all pass through
# these three functions, so the rules - what counts as a link, how many, how long
# - live in one place. Every link is checked on the way out of the database as
# well as on the way in, since a row edited by hand in D1 must not be able to
# put a ``javascript:`` address on somebody's profile.


def normalise_social_url(value):
    """``(url, problem)`` for one link somebody typed.

    A bare ``youtube.com/@someone`` is accepted and given an https scheme - no
    one types the scheme into a "your channel" box - and anything that is not an
    http(s) address on a public domain is refused with the reason.

    The value is not assumed to be a string: this also validates what comes back
    out of the JSON column, where a hand-edited row can hold absolutely anything,
    and a number or a nested object must not be able to raise its way out of a
    profile render.
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    value = value.strip()
    if not value:
        return "", ""
    if len(value) > MAX_SOCIAL_URL:
        return "", f"links must be {MAX_SOCIAL_URL} characters or fewer."
    if re.search(r"\s", value):
        return "", "links cannot contain spaces."
    if value.startswith("//"):
        value = "https:" + value
    elif not value.lower().startswith(("http://", "https://")):
        value = "https://" + value.lstrip("/")
    if not is_public_url(value):
        return "", (
            "that is not a link we can use - include the domain,"
            " for example youtube.com/@you."
        )
    return value, ""


def parse_social_links(form):
    """``(links, problem)`` from the profile form's social boxes.

    One problem is enough to refuse the whole save, so a typo is never silently
    dropped: the editor says which box it came from and nothing is written.
    """
    links = []
    for key, label, _placeholder in SOCIAL_PLATFORMS:
        url, problem = normalise_social_url(form.get(f"social_{key}"))
        if problem:
            return None, f"{label}: {problem}"
        if url:
            links.append({"platform": key, "label": label, "url": url})
    # Free-form rows for everything without a box of its own. A row counts when
    # it holds a link; its name is optional and falls back to the link's domain,
    # so "mediafire.com/you" does not need a label typed next to it.
    for index in range(1, MAX_OTHER_SOCIAL_LINKS + 1):
        label = (form.get(f"other_label_{index}") or "").strip()[:MAX_SOCIAL_LABEL]
        url, problem = normalise_social_url(form.get(f"other_url_{index}"))
        if problem:
            return None, f"Other links, row {index}: {problem}"
        if not url:
            continue
        links.append({
            "platform": "other",
            "label": label or site_label(url) or "Link",
            "url": url,
        })
    return links[:MAX_SOCIAL_LINKS], ""


def display_social_url(url):
    """A link as it reads on a profile: no scheme, no trailing slash.

    The About card shows the address rather than just the platform name, since
    "YouTube" says nothing about *which* channel and the host usually does.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    tail = parts.path.rstrip("/")
    if parts.query:
        tail += "?" + parts.query
    return (host + tail)[:80] or url


def social_links_of(user):
    """The links stored on a user row, ready to render - possibly empty.

    Anything unreadable is dropped instead of reported: this runs on every
    profile view, and a row somebody edited by hand should be able to make a
    link disappear but never to break the page.
    """
    raw = user.get("social_links") if user else None
    if not raw:
        return []
    try:
        stored = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(stored, list):
        return []
    links = []
    for item in stored:
        if not isinstance(item, dict):
            continue
        url, problem = normalise_social_url(item.get("url"))
        if problem or not url:
            continue
        # A platform key that is missing, unknown or not even a string falls back
        # to "other" - which is also what the editor's free rows use.
        key = item.get("platform")
        if not isinstance(key, str) or key not in SOCIAL_LABELS:
            key = "other"
        label = item.get("label")
        label = label.strip()[:MAX_SOCIAL_LABEL] if isinstance(label, str) else ""
        links.append({
            "platform": key,
            # A known platform always shows its own name; only an "other" link
            # carries a label the user chose.
            "label": SOCIAL_LABELS.get(key) or label or site_label(url) or "Link",
            "url": url,
            "display": display_social_url(url),
        })
        if len(links) >= MAX_SOCIAL_LINKS:
            break
    return links


def profile_user(username):
    """The profile row for ``username``, or a 404 for an unknown account.

    Deleted accounts 404 like unknown ones: their handle was released, so there
    is no profile left to show and no way to reach one.
    """
    user = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
    if not user or user.get("deleted_at"):
        abort(404)
    return user


@app.route("/profile/<username>")
def profile(username):
    user = profile_user(username)
    state = viewer_follow_state(user)
    viewer_id = state["viewer_id"]
    clause, params = visibility_sql(viewer_id)
    comments = query(f"""
        SELECT comments.content, comments.created_at, posts.id AS post_id, posts.title,
               posts.public_id AS public_id, users.user_id AS author_public_id
        FROM comments JOIN posts ON posts.id=comments.post_id
        LEFT JOIN users ON users.id = posts.user_id
        WHERE comments.user_id=? AND {clause}
        ORDER BY comments.created_at DESC LIMIT 20
    """, user["id"], *params)
    posts = fetch_posts(
        f"WHERE {clause} AND posts.user_id=?",
        tuple(params + [user["id"]]),
        order="posts.pinned DESC, posts.id DESC",
    )
    photo_total = 0
    if gplus_schema():
        row = safe_first(
            "SELECT COUNT(*) AS total FROM post_images JOIN posts"
            " ON posts.id = post_images.post_id"
            " WHERE posts.user_id=? AND posts.status='published'",
            user["id"],
        )
        photo_total = int(row["total"]) if row else 0
    return render_template(
        "profile.html",
        user=user,
        posts=posts,
        comments=comments,
        socials=social_links_of(user),
        collections=collection_rows(user["id"], viewer_id),
        photo_total=photo_total,
        blocked=viewer_blocks(current_user(), user["id"]),
        in_circle=circle_of_author_for(viewer_id, user["id"]),
        muted=is_muted(viewer_id, user["id"]),
        albums=albums_for(user["id"], viewer_id),
        **state,
        follower_people=follow_list(
            user["id"], "followers", state["viewer_id"], FOLLOW_PREVIEW_LIMIT
        ),
        following_people=follow_list(
            user["id"], "following", state["viewer_id"], FOLLOW_PREVIEW_LIMIT
        ),
    )


def connections_page(username, direction):
    """The full followers or following list behind a profile's "View all" link."""
    user = profile_user(username)
    state = viewer_follow_state(user)
    return render_template(
        "connections.html",
        user=user,
        direction=direction,
        people=follow_list(user["id"], direction, state["viewer_id"]),
        **state,
    )


@app.route("/profile/<username>/followers")
def followers(username):
    return connections_page(username, "followers")


@app.route("/profile/<username>/following")
def following(username):
    return connections_page(username, "following")


@app.route("/follow/<username>", methods=["POST"])
@login_required
def follow(username):
    """Follow or unfollow: the same button toggles, like the vote buttons do."""
    user = first(
        "SELECT id, username, display_name FROM users WHERE username=? COLLATE NOCASE",
        username,
    )
    if not user:
        abort(404)
    viewer_id = session["user_db_id"]
    # A block closes the relationship in both directions; following somebody you
    # have blocked (or who has blocked you) is refused here, not just hidden in a
    # template.
    if user["id"] != viewer_id and is_blocked(viewer_id, user["id"]):
        flash("You cannot follow that account.", "error")
        return redirect(safe_next(
            request.form.get("next"), url_for("profile", username=user["username"])
        ))
    # Following yourself is refused here rather than at the button, so a hand-made
    # request cannot create a row the site would then have to render around.
    if user["id"] != viewer_id:
        if is_following(viewer_id, user["id"]):
            execute(
                "DELETE FROM follows WHERE follower_id=? AND followed_id=?",
                viewer_id, user["id"],
            )
            flash(f"You unfollowed {user['display_name']}.", "success")
        else:
            # OR IGNORE covers a double submit racing the same insert.
            execute(
                "INSERT OR IGNORE INTO follows (follower_id, followed_id)"
                " VALUES (?, ?)",
                viewer_id, user["id"],
            )
            notify(user["id"], "follow", viewer_id)
            flash(f"You are now following {user['display_name']}.", "success")
    return redirect(safe_next(
        request.form.get("next"), url_for("profile", username=user["username"])
    ))


@app.route("/settings/profile", methods=["GET", "POST"])
@login_required
def profile_settings():
    user = current_user()
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        bio = request.form.get("bio", "").strip()
        tagline = request.form.get("tagline", "").strip()
        nickname = request.form.get("nickname", "").strip()
        # The About card's free-text fields, kept in one dict so the column names
        # and the form names cannot drift apart.
        about = {
            "about_work": request.form.get("about_work", "").strip(),
            "about_education": request.form.get("about_education", "").strip(),
            "about_places": request.form.get("about_places", "").strip(),
            "about_relationship": request.form.get("about_relationship", "").strip(),
            "about_birthday": request.form.get("about_birthday", "").strip(),
            "about_gender": request.form.get("about_gender", "").strip(),
            "about_contact": request.form.get("about_contact", "").strip(),
            "bragging_rights": request.form.get("bragging_rights", "").strip(),
        }
        cover_position = request.form.get("cover_position", "center")
        if cover_position not in ("center", "top", "bottom"):
            cover_position = "center"
        if not 1 <= len(display_name) <= 40:
            flash("Display name must be 1–40 characters.", "error")
        elif len(bio) > MAX_BIO_LENGTH:
            flash(f"Your bio must be {MAX_BIO_LENGTH} characters or fewer.", "error")
        elif len(tagline) > MAX_TAGLINE_LENGTH:
            flash(f"Your tagline must be {MAX_TAGLINE_LENGTH} characters or fewer.", "error")
        elif len(nickname) > MAX_NICKNAME_LENGTH:
            flash(f"A nickname must be {MAX_NICKNAME_LENGTH} characters or fewer.", "error")
        elif any(len(value) > MAX_ABOUT_LENGTH for value in about.values()):
            flash(f"Each About line must be {MAX_ABOUT_LENGTH} characters or fewer.", "error")
        else:
            links, link_error = parse_social_links(request.form)
            picture, picture_error = save_image_upload(request.files.get("profile_picture"))
            banner, banner_error = save_image_upload(request.files.get("banner"))
            upload_error = link_error or picture_error or banner_error
            if upload_error:
                # Do not keep whichever half of the upload did succeed.
                for stored in (picture, banner):
                    delete_upload(stored)
                flash(upload_error, "error")
            else:
                fields = {
                    "display_name": display_name,
                    "bio": bio or None,
                    "tagline": tagline or None,
                    "nickname": nickname or None,
                    "cover_position": cover_position,
                    # The list is only ever read and written as a whole, so it
                    # lives in one JSON column instead of its own table.
                    "social_links": json.dumps(links) if links else None,
                    **{column: value or None for column, value in about.items()},
                }
                removed = []
                if picture:
                    fields["profile_picture"] = picture
                    removed.append(user["profile_picture"])
                elif request.form.get("remove_profile_picture"):
                    fields["profile_picture"] = None
                    removed.append(user["profile_picture"])
                if banner:
                    fields["banner"] = banner
                    removed.append(user["banner"])
                elif request.form.get("remove_banner"):
                    fields["banner"] = None
                    removed.append(user["banner"])

                # A database that has not had migration 0016 applied cannot take
                # the new profile columns; the old form fields still save.
                if not gplus_schema():
                    for column in ("tagline", "nickname", "cover_position",
                                   "about_work", "about_education", "about_places",
                                   "about_relationship", "about_birthday",
                                   "about_gender", "about_contact",
                                   "bragging_rights"):
                        fields.pop(column, None)
                # Column names come from the literals above, not from input.
                assignments = ", ".join(f"{column}=?" for column in fields)
                execute(
                    f"UPDATE users SET {assignments} WHERE id=?",
                    *fields.values(), user["id"],
                )
                for filename in removed:
                    delete_upload(filename)
                flash("Profile updated.", "success")
                return redirect(url_for("profile_settings"))
    # The editor shows what is stored, with a blank row for every "other" slot
    # still going spare, and names its boxes after the same platform table the
    # parser reads, so the two cannot drift apart.
    socials = social_links_of(user)
    other_rows = [link for link in socials if link["platform"] == "other"]
    return render_template(
        "profile_settings.html",
        user=user,
        max_bio_length=MAX_BIO_LENGTH,
        social_platforms=SOCIAL_PLATFORMS,
        social_values={link["platform"]: link["url"] for link in socials},
        other_rows=(
            other_rows
            + [{"label": "", "url": ""}] * (MAX_OTHER_SOCIAL_LINKS - len(other_rows))
        ),
        max_other_links=MAX_OTHER_SOCIAL_LINKS,
        max_social_url=MAX_SOCIAL_URL,
        max_social_label=MAX_SOCIAL_LABEL,
        max_tagline=MAX_TAGLINE_LENGTH,
        max_nickname=MAX_NICKNAME_LENGTH,
        max_about=MAX_ABOUT_LENGTH,
    )


# Site settings ---------------------------------------------------------------
# One page, three audiences. "Appearance" is for everybody including anonymous
# visitors (the theme lives in the browser, see public/static/theme.js), the
# account section is a signpost for signed-in people, and the owner panel is
# rendered only for OWNER_USERNAMES. Everything behind that panel is read-only
# except the link-card rebuild, which reuses the admin panel's own routine.


def site_stats():
    """Every count the owner panel shows, in a single round trip to D1.

    Failure is not fatal by design: the two moderation counts read columns that
    migration 0009 adds, and the deploy that ships this code does not run
    migrations (CI ships code only), so a database that has not caught up yet
    leaves the panel's tiles blank rather than turning the whole page into a 500.
    """
    try:
        row = first(SITE_STATS_SQL)
    except Exception as exc:  # pragma: no cover - depends on the database state
        app.logger.warning("Site stats unavailable, running migration 0009? %s", exc)
        return {}
    return row or {}


SITE_STATS_SQL = """
        SELECT (SELECT COUNT(*) FROM users) AS users,
               (SELECT COUNT(*) FROM posts) AS posts,
               (SELECT COUNT(*) FROM posts WHERE status='published') AS published,
               (SELECT COUNT(*) FROM posts WHERE status<>'published') AS drafts,
               (SELECT COUNT(*) FROM posts WHERE user_id IS NULL) AS orphan_posts,
               (SELECT COUNT(*) FROM comments) AS comments,
               (SELECT COUNT(*) FROM post_votes) AS votes,
               (SELECT COUNT(*) FROM follows) AS follows,
               (SELECT COUNT(*) FROM uploads) AS uploads,
               (SELECT COALESCE(SUM(size), 0) FROM uploads) AS upload_bytes,
               (SELECT COUNT(*) FROM link_previews) AS link_cards,
               (SELECT COUNT(*) FROM link_previews WHERE image IS NOT NULL) AS link_images,
               (SELECT COUNT(*) FROM users WHERE deleted_at IS NOT NULL) AS deleted_users,
               (SELECT COUNT(*) FROM users
                 WHERE account_ban_permanent=1
                    OR (account_ban_until IS NOT NULL AND account_ban_until > datetime('now')))
                   AS banned_accounts,
               (SELECT COUNT(*) FROM users
                 WHERE comment_ban_permanent=1
                    OR (comment_ban_until IS NOT NULL AND comment_ban_until > datetime('now')))
                   AS comment_bans,
               (SELECT COUNT(*) FROM users
                 WHERE post_ban_permanent=1
                    OR (post_ban_until IS NOT NULL AND post_ban_until > datetime('now')))
                   AS post_bans
"""


def owner_drafts(limit=10):
    """Unpublished posts, newest first - the ones nobody else can find."""
    return query(f"""
        SELECT posts.id, posts.title, posts.category, posts.status,
               posts.created_at, posts.public_id AS public_id,
               users.username AS author_username,
               users.user_id AS author_public_id
        FROM posts LEFT JOIN users ON users.id = posts.user_id
        WHERE posts.status <> 'published'
        ORDER BY posts.created_at DESC, posts.id DESC
        LIMIT {int(limit)}
    """)


def recent_signups(limit=8):
    """The newest accounts, so the owner can see who has joined."""
    return query(f"""
        SELECT users.username, users.display_name, users.created_at,
               users.profile_picture,
               (SELECT COUNT(*) FROM posts WHERE posts.user_id=users.id) AS post_count,
               (SELECT COUNT(*) FROM follows WHERE follows.followed_id=users.id)
                   AS follower_count
        FROM users
        ORDER BY users.created_at DESC, users.id DESC
        LIMIT {int(limit)}
    """)


def owner_config():
    """The effective values this Worker is running with, for the owner panel.

    Read-only by design: these come from wrangler.jsonc, the dashboard or the
    code, so showing them here is how the owner checks what is actually live
    without opening the Cloudflare dashboard.
    """
    worker_env = env()
    admin_secret = getattr(worker_env, "ADMIN_PASSWORD", None)
    return [
        ("Owner accounts", ", ".join(sorted(owner_usernames())) or "(none)"),
        ("Admin password", "set" if admin_secret else "not set (using the default)"),
        ("Password work factor", f"{password_iterations():,} PBKDF2 iterations"),
        ("Max image size", f"{MAX_IMAGE_BYTES // 1000} KB"),
        ("Remember-me sessions", f"{REMEMBER_SESSION_DAYS} days"),
        ("Link cards", f"refreshed after {LINK_PREVIEW_TTL_SECONDS // 86400} days, "
                        f"{MAX_LINK_REFRESH_PER_RUN} per rebuild"),
    ]


@app.route("/settings")
def settings():
    """Settings: appearance for everyone, owner tools only for the site owner."""
    owner = is_owner()
    context = {"owner": owner}
    if owner:
        context.update(
            stats=site_stats(),
            drafts=owner_drafts(),
            signups=recent_signups(),
            config=owner_config(),
            max_link_refresh=MAX_LINK_REFRESH_PER_RUN,
            commit_repo=commit_repo(),
            commit_ttl_minutes=COMMIT_LOG_TTL_SECONDS // 60,
        )
    return render_template("settings.html", **context)


@app.post("/settings/refresh-links")
@owner_required
def settings_refresh_links():
    """Owner-only: rebuild every link card without leaving the settings page."""
    checked, cards = refresh_link_cards()
    flash_refresh_result(checked, cards)
    return redirect(url_for("settings") + "#owner")


@app.post("/settings/refresh-commits")
@owner_required
def settings_refresh_commits():
    """Owner-only: read the commit log again, right now.

    The log also refreshes itself when an update post is opened, but that waits
    out COMMIT_LOG_TTL_SECONDS first, and this is the button that does not.
    """
    refresh_commit_log(force=True)
    state = first("SELECT succeeded FROM commit_sync WHERE id=1")
    total = first("SELECT COUNT(*) AS total FROM commit_log")
    count = total["total"] if total else 0
    if state and state["succeeded"]:
        flash(
            f"Commit log refreshed - {count} commit{'' if count == 1 else 's'}.",
            "success",
        )
    else:
        flash(
            "GitHub did not answer with commits, so the log is unchanged. "
            "Unauthenticated reads are limited per IP address - try again later.",
            "error",
        )
    return redirect(url_for("settings") + "#owner")


@app.route("/settings/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    """The second half of deleting an account: an explicit confirmation page.

    The button in settings only links here - nothing is destroyed by following a
    link. This page asks for two separate deliberate acts before it does
    anything: typing the username and ticking the acknowledgement. There is no
    undo, and the handle becomes free for anyone else to register.
    """
    user = current_user()
    if user.get("deleted_at"):
        session.clear()
        return redirect(url_for("home"))
    if request.method == "POST":
        typed = request.form.get("confirm_username", "").strip()
        if not request.form.get("understand"):
            flash("Tick the box to confirm you understand this cannot be undone.", "error")
        elif typed.lower() != (user["username"] or "").lower():
            flash("Type your username exactly to confirm it is you.", "error")
        else:
            anonymise_account(user)
            session.clear()
            flash("Your account has been deleted. Your posts and comments are still "
                  f"here, shown as {DELETED_ACCOUNT_NAME}.", "success")
            return redirect(url_for("home"))
    return render_template(
        "delete_account.html",
        user=user,
        deleted_name=DELETED_ACCOUNT_NAME,
        owner_account=is_owner_username(user["username"]),
    )


# Messages -------------------------------------------------------------------
# The inbox lists conversations, a conversation is a thread of messages, and every
# route takes the reader's own id rather than trusting one from the address bar.
# Opening a thread is what marks it read; there is no separate step to forget.


def conversation_heading(other):
    """Everything a thread's header needs about the person on the other side."""
    return {
        "id": (other or {}).get("id"),
        "username": (other or {}).get("username"),
        "display_name": (other or {}).get("display_name") or "an account",
        "profile_picture": (other or {}).get("profile_picture"),
        "deleted_at": (other or {}).get("deleted_at"),
    }


def conversation_body_error(body):
    """Why a typed message cannot be sent, or None when it can."""
    if not body:
        return "Write something first."
    if len(body) > MAX_DM_LENGTH:
        return f"A message can be up to {MAX_DM_LENGTH} characters."
    return None


@app.route("/messages")
@login_required
def messages():
    """The inbox: every conversation, newest first, plus any unthreaded notices."""
    user = current_user()
    return render_template(
        "messages.html",
        threads=conversations_for(user),
        notices=standalone_notices(user["id"]),
        unread=unread_messages(user),
        moderation_id=(moderation_account() or {}).get("id"),
    )


@app.post("/messages/start")
@login_required
def start_conversation():
    """Open the inbox's "new message" box: find the account, then go to the thread."""
    username = request.form.get("to", "").strip().lstrip("@")
    if not username:
        flash("Type the username of the person you want to message.", "error")
        return redirect(url_for("messages"))
    target = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
    if not target or target.get("deleted_at"):
        flash(f"There is no account called @{username}.", "error")
        return redirect(url_for("messages"))
    if is_blocked(current_user()["id"], target["id"]):
        flash("You cannot message that account.", "error")
        return redirect(url_for("messages"))
    return redirect(url_for("new_conversation", username=target["username"]))


@app.route("/messages/new/<username>", methods=["GET", "POST"])
@login_required
def new_conversation(username):
    """Start a conversation with somebody.

    Nothing is written until the first message is sent, so following a link from a
    profile cannot litter the database with empty threads; sending is what creates
    the conversation.
    """
    user = current_user()
    target = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
    if not target or target.get("deleted_at"):
        abort(404)
    if target["id"] == user["id"]:
        flash("That is your own account - there is nobody to message.", "error")
        return redirect(url_for("profile", username=user["username"]))
    if is_blocked(user["id"], target["id"]):
        flash("You cannot message that account.", "error")
        return redirect(url_for("messages"))
    existing = conversation_between(user["id"], target["id"])
    if existing:
        if request.method == "POST":
            # A page opened from a profile before the first message landed, or a
            # conversation somebody already had: handle the send in the thread that
            # exists rather than bouncing the typed line into a redirect. The thread
            # view is called by name, so nothing local may be called `conversation`
            # here - a same-named local would shadow it and raise UnboundLocalError.
            return conversation(existing["id"])
        return redirect(url_for("conversation", conversation_id=existing["id"]))
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        error = conversation_body_error(body)
        if error:
            flash(error, "error")
        else:
            thread = open_conversation(user["id"], target["id"])
            if not thread:
                flash("Messages are not available right now - has migration 0015 "
                      "been applied to this database?", "error")
                return redirect(url_for("messages"))
            send_direct_message(thread, user, body)
            return redirect(url_for("conversation", conversation_id=thread["id"]) + "#bottom")
    return render_template(
        "conversation.html",
        # No thread exists yet, so nothing in the list is the open one - but the
        # right pane is open all the same, holding the first message being typed.
        threads=conversations_for(user),
        notices=standalone_notices(user["id"]),
        unread=unread_messages(user),
        selected=None,
        composing=True,
        conversation=None,
        other=target,
        heading=conversation_heading(target),
        thread_messages=[],
        my_side_id=user["id"],
        can_post=True,
        standing_in=False,
        moderation_id=(moderation_account() or {}).get("id"),
    )


@app.route("/messages/c/<int:conversation_id>", methods=["GET", "POST"])
def conversation(conversation_id):
    """One thread, oldest message first; sending appends to it.

    Open to a signed-in participant and to an admin, who is who the site's own
    thread is for: the shared ADMIN_PASSWORD is not an account, so it carries no
    inbox of its own, and the moderation account has no session - this route is
    where the two meet. Everybody else gets a 404 from the visibility check below.
    """
    user = current_user()
    if not user and not is_admin():
        flash("You need to be logged in to do that.", "error")
        return redirect(url_for("login", next=request.path))
    thread = conversation_by_id(conversation_id)
    if not thread or not may_view_conversation(thread, user):
        abort(404)
    account = moderation_account()
    mine = conversation_is_participant(thread, user)
    # An admin may not only read the site's thread, they may answer it: the panel is
    # the moderation account's keyboard, since that account has no session of its
    # own. Writing there is writing *as* the site, which is why the bubbles still
    # line up on the site's side of the thread.
    standing_in = bool(not mine and is_admin() and conversation_with_moderation(thread))
    can_post = mine or standing_in
    if request.method == "POST":
        if not can_post:
            flash("Only the two people in a conversation can post to it.", "error")
            return redirect(url_for("conversation", conversation_id=conversation_id))
        # A block still lets the two of them read what was already said, but it
        # closes the thread to anything new - the same rule G+ applied.
        other_id = conversation_other_id(thread, user["id"] if mine else 0)
        if mine and other_id and is_blocked(user["id"], other_id):
            flash("You cannot message that account.", "error")
            return redirect(url_for("conversation", conversation_id=conversation_id))
        body = request.form.get("body", "").strip()
        error = conversation_body_error(body)
        if error:
            flash(error, "error")
            return redirect(url_for("conversation", conversation_id=conversation_id))
        send_direct_message(thread, user if mine else account, body)
        return redirect(url_for("conversation", conversation_id=conversation_id) + "#bottom")
    # Whoever is reading is one of the two voices in the thread: their own account,
    # or the site's when an admin is standing in for it. Marking that side read is
    # what opening a conversation means - and it is why the page an admin reads
    # cannot clear the other person's unread badge.
    my_side_id = user["id"] if mine else (account or {}).get("id")
    mark_conversation_read(thread, [my_side_id])
    other = user_by_id(conversation_other_id(thread, my_side_id or 0)) or {}
    rows = conversation_messages(thread["id"])
    return render_template(
        "conversation.html",
        # The list beside the thread is the same one the inbox shows, which is
        # what makes the page read as one screen: pick another person on the left
        # and the pane on the right changes.
        threads=inbox_threads(user, standing_in=standing_in),
        notices=standalone_notices(user["id"]) if user else [],
        unread=unread_messages(user),
        selected=thread["id"],
        conversation=thread,
        other=other,
        heading=conversation_heading(other),
        thread_messages=rows,
        ban_states=thread_ban_states(thread, rows),
        # Which side of the thread the viewer's own messages are on: their account,
        # or the site's when an admin is writing for it.
        my_side_id=my_side_id,
        viewer=user,
        can_post=can_post,
        standing_in=standing_in,
        moderation_id=(account or {}).get("id"),
        moderation=account,
    )


@app.route("/messages/<int:message_id>")
@login_required
def message(message_id):
    """One notice by its own address.

    A notice that belongs to a conversation is not a page of its own any more - it
    is one message in a thread - so this sends the reader there (the thread decides
    what it may mark read, which is why an admin peeking cannot clear somebody
    else's unread badge). The unthreaded notices written before the moderation
    account existed are still rendered here.
    """
    user = current_user()
    item = message_for(user["id"], message_id) or message_by_id(message_id)
    if not item or not message_visible(item, user):
        abort(404)
    if item.get("conversation_id"):
        return redirect(url_for("conversation", conversation_id=item["conversation_id"])
                        + f"#message-{item['id']}")
    if item.get("recipient_id") == user["id"] and not item.get("read_at"):
        try:
            execute("UPDATE messages SET read_at=datetime('now') WHERE id=?", message_id)
        except Exception as exc:
            app.logger.warning("Could not mark message %s read: %s", message_id, exc)
        item = message_by_id(message_id) or item
    # Whether the ban this message records is still in force is asked at read
    # time, not baked into the notice: a temporary ban that has since run out (or
    # one an admin lifted) must not keep telling somebody they are banned.
    live = bool(item.get("ban_kind")) and is_banned(user, item["ban_kind"])
    return render_template("message.html", message=item, ban_live=live)


@app.post("/messages/read")
@login_required
def read_messages():
    """Mark the whole inbox read without opening every message."""
    try:
        execute("UPDATE messages SET read_at=datetime('now') "
                "WHERE recipient_id=? AND read_at IS NULL", current_user()["id"])
    except Exception as exc:
        app.logger.warning("Could not mark messages read: %s", exc)
    flash("All caught up.", "success")
    return redirect(url_for("messages"))


@app.post("/messages/<int:message_id>/delete")
@login_required
def delete_message(message_id):
    """Remove one of your own messages. It is gone for you, not for the log."""
    try:
        execute("DELETE FROM messages WHERE id=? AND recipient_id=?",
                message_id, current_user()["id"])
    except Exception as exc:
        app.logger.warning("Could not delete message %s: %s", message_id, exc)
        flash("That message could not be deleted.", "error")
        return redirect(url_for("messages"))
    flash("Message deleted.", "success")
    return redirect(url_for("messages"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == admin_password():
            session["admin"] = True
            return redirect(url_for("admin"))
        flash("Incorrect password.", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("home"))


@app.route("/admin")
@admin_required
def admin():
    posts = query("""
        SELECT posts.*, users.username AS author_username,
               users.user_id AS author_public_id
        FROM posts LEFT JOIN users ON users.id = posts.user_id
        ORDER BY posts.created_at DESC
    """)
    comments = query("""
        SELECT comments.*, posts.title AS post_title,
               users.username, users.display_name
        FROM comments
        JOIN posts ON posts.id = comments.post_id
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.created_at DESC
    """)
    users = query("SELECT * FROM users ORDER BY created_at DESC")
    # What each account's current ban was for, and every moderation action on
    # record: migration 0009's columns on `users` only remember the last ban, and
    # nothing at all about what caused it.
    reports = safe_query("""
        SELECT reports.*, reporter.username AS reporter_username,
               target.username AS target_username,
               target.display_name AS target_name,
               posts.title AS post_title, posts.public_id AS post_public_id,
               comments.content AS comment_content
        FROM reports
        LEFT JOIN users reporter ON reporter.id = reports.reporter_id
        LEFT JOIN users target ON target.id = reports.target_user_id
        LEFT JOIN posts ON posts.id = reports.post_id
        LEFT JOIN comments ON comments.id = reports.comment_id
        WHERE reports.resolved_at IS NULL
        ORDER BY reports.id DESC LIMIT 50
    """) if gplus_schema() else []
    return render_template(
        "admin.html",
        posts=posts, comments=comments, users=users,
        causes=latest_ban_causes(),
        history=moderation_history(),
        content_by_user=moderatable_content(users),
        moderation=moderation_account(),
        moderation_threads=moderation_threads(),
        reports=reports,
        gplus=gplus_schema(),
        email_ready=email_configured(),
        email_pending=pending_email_count(),
        email_recent=safe_query(
            "SELECT * FROM email_outbox ORDER BY id DESC LIMIT 12"
        ) if gplus2_schema() else [],
    )


@app.post("/admin/delete-comment/<int:comment_id>")
@admin_required
def delete_comment(comment_id):
    execute("DELETE FROM comments WHERE id=?", comment_id)
    return redirect(url_for("admin") + "#comments")


def refresh_link_cards(max_posts=MAX_LINK_REFRESH_PER_RUN):
    """Re-fetch the link cards for posts that contain a URL.

    Covers posts written before link cards existed, and refresh is what makes a
    card whose target page was down resolvable later without editing the post.
    Shared by the admin panel and the owner settings panel; returns
    ``(checked, rebuilt)`` so each caller can word its own flash message.
    """
    rows = query("SELECT id, content FROM posts ORDER BY id DESC")
    checked = cards = 0
    for row in rows:
        if checked >= max_posts:
            break
        url = extract_post_link(row["content"], request.host.split(":")[0])
        if not url:
            continue
        checked += 1
        if ensure_link_preview(url, force=True):
            cards += 1
        execute("UPDATE posts SET link_url=? WHERE id=?", url, row["id"])
    return checked, cards


def flash_refresh_result(checked, cards):
    """Tell the editor what a link-card rebuild did (or that there was nothing)."""
    if not checked:
        flash("No posts with links to refresh.", "error")
    else:
        flash(f"Checked {checked} link{'s' if checked != 1 else ''}, "
              f"rebuilt {cards} card{'s' if cards != 1 else ''}.", "success")


@app.post("/admin/refresh-links")
@admin_required
def admin_refresh_links():
    """Admin panel entry point for the shared link-card rebuild."""
    checked, cards = refresh_link_cards()
    flash_refresh_result(checked, cards)
    return redirect(url_for("admin") + "#posts")


@app.post("/admin/users/<int:user_id>/ban")
@admin_required
def admin_ban_user(user_id):
    """Hand out one of the six bans: a kind, a duration, and optionally why."""
    target = first("SELECT * FROM users WHERE id=?", user_id)
    block = moderation_block(target)
    if block:
        flash(block, "error")
        return redirect(url_for("admin") + "#users")
    choice = BAN_CHOICES.get(request.form.get("ban", ""))
    if not choice:
        flash("Pick a ban to apply first.", "error")
        return redirect(url_for("admin") + "#users")
    kind, permanent, label = choice
    until = None
    if not permanent:
        duration = request.form.get("duration", DEFAULT_BAN_DURATION)
        if duration not in BAN_DURATIONS:
            duration = DEFAULT_BAN_DURATION
        until = (utcnow() + BAN_DURATIONS[duration][1]).strftime(DB_TIME_FORMAT)
    reason = request.form.get("reason", "").strip()[:BAN_REASON_MAX]
    # The post or comment this ban is for. Optional - an admin can ban somebody
    # without pointing at anything - but when it is given it is stored with the
    # ban and quoted in the notice, so "what did they do?" has an answer that
    # outlives the comment itself.
    content = parse_moderation_content(request.form.get("content", ""))
    until_column, permanent_column = ban_columns(kind)
    me = current_user()
    actor = (me or {}).get("username") or "admin"
    try:
        execute(
            f"""UPDATE users SET {until_column}=?, {permanent_column}=?, ban_reason=?,
                                banned_at=datetime('now'), banned_by=?
               WHERE id=?""",
            until, 1 if permanent else 0, reason or None,
            actor, target["id"],
        )
    except Exception as exc:  # most likely: migration 0009 has not been applied
        app.logger.warning("Could not ban user %s: %s", target["id"], exc)
        flash("The ban could not be saved. Has `npm run db:remote` been run for this "
              "database?", "error")
        return redirect(url_for("admin") + "#users")
    # The ban is saved first, and the notice is a side effect of it: a missing
    # messages table must never be the reason a ban did not take effect.
    told = send_ban_notice(target, kind, permanent, until, reason, content, actor)
    where = f" until {until} UTC" if until else " permanently"
    flash(
        f"{label} applied to {target['display_name']}{where}. "
        + ("A notice was sent to their inbox." if told
           else "The notice could not be sent - has migration 0014 been applied?"),
        "success" if told else "error",
    )
    return redirect(url_for("admin") + "#users")


@app.post("/admin/users/<int:user_id>/message")
@admin_required
def admin_message_user(user_id):
    """Write into somebody's inbox as the site, by hand.

    Sent as the moderation account rather than as whoever happens to be holding
    the admin password, because the panel is the site speaking: the message lands
    in the same thread as that account's notices, so an admin answering a reply
    answers it in the conversation it came from. What the admin is called is kept
    in the moderation log either way.
    """
    target = first("SELECT * FROM users WHERE id=?", user_id)
    if not target or target.get("deleted_at"):
        flash("That account cannot receive messages.", "error")
        return redirect(url_for("admin") + "#users")
    body = request.form.get("body", "").strip()
    error = conversation_body_error(body)
    if error:
        flash(error, "error")
        return redirect(url_for("admin") + "#users")
    account = moderation_account()
    if not account or account["id"] == target["id"]:
        flash(f"There is no {moderation_username()} account to write as, so the "
              "site cannot send this.", "error")
        return redirect(url_for("admin") + "#users")
    conversation = open_conversation(account["id"], target["id"])
    if not conversation:
        flash("The message could not be sent. Has migration 0015 been applied?", "error")
        return redirect(url_for("admin") + "#users")
    content = parse_moderation_content(request.form.get("content", ""))
    message_id = send_message(
        target["id"], "", body, sender=account, kind="message", about=content,
        conversation_id=conversation["id"],
    )
    if not message_id:
        flash("The message could not be sent. Has migration 0015 been applied?", "error")
        return redirect(url_for("admin") + "#users")
    moderation_record(target["id"], "message", acted_by=actor_name(current_user()),
                      content=content, message_id=message_id)
    # Flashes are escaped, so this points at the thread in words rather than with
    # markup - the moderation inbox below it is where it can be opened.
    flash(f"Message sent to {target['display_name']} as "
          f"{account['display_name']}.", "success")
    return redirect(url_for("admin") + "#moderation")


@app.post("/admin/users/<int:user_id>/unban")
@admin_required
def admin_unban_user(user_id):
    """Lift one kind of ban, or every kind at once."""
    target = first("SELECT * FROM users WHERE id=?", user_id)
    if not target:
        abort(404)
    requested = request.form.get("kind", "all")
    kinds = (requested,) if requested in BAN_KINDS else BAN_KINDS
    assignments = []
    for kind in kinds:
        until_column, permanent_column = ban_columns(kind)
        assignments.append(f"{until_column}=NULL")
        assignments.append(f"{permanent_column}=0")
    try:
        execute(f"UPDATE users SET {', '.join(assignments)} WHERE id=?", target["id"])
    except Exception as exc:
        app.logger.warning("Could not lift bans for %s: %s", target["id"], exc)
        flash("The bans could not be lifted. Has `npm run db:remote` been run for "
              "this database?", "error")
        return redirect(url_for("admin") + "#users")
    # A ban that lifts itself (a temporary one whose expiry passes) sends nothing:
    # the person simply finds they can comment again. This only fires when an
    # admin actively lifted it, which is the case worth telling somebody about.
    told = send_unban_notice(target, kinds, actor_name(current_user()))
    flash(
        f"Lifted the ban on {target['display_name']}. "
        + ("They were told in their inbox." if told
           else "The notice could not be sent - has migration 0014 been applied?"),
        "success" if told else "error",
    )
    return redirect(url_for("admin") + "#users")


# Google+ revival: circles, collections, communities, events ---------------------
# The screens G+ built its social graph out of. Every one of them is a thin
# layer over the tables migration 0016 adds; the streams themselves reuse
# fetch_posts() and visibility_sql(), so a circle post is filtered by the same
# rule everywhere it can appear.


def revival_ready():
    """False (with an explanation) when migration 0016 has not been applied."""
    if gplus_schema():
        return True
    flash("That part of the site needs the newest database migration. Run "
          "`npm run db:remote` and reload.", "error")
    return False


@app.route("/circles")
@login_required
def circles():
    """Manage the circles G+ organised everybody into."""
    if not revival_ready():
        return redirect(url_for("home"))
    user = current_user()
    rows = circle_rows(user["id"])
    members = {row["id"]: circle_member_rows(row["id"]) for row in rows}
    return render_template(
        "circles.html",
        circles=rows,
        members=members,
        max_circle_name=MAX_CIRCLE_NAME,
    )


@app.post("/circles/create")
@login_required
def create_circle():
    if not revival_ready():
        return redirect(url_for("home"))
    name = request.form.get("name", "").strip()
    if not 1 <= len(name) <= MAX_CIRCLE_NAME:
        flash(f"A circle needs a name of 1-{MAX_CIRCLE_NAME} characters.", "error")
    else:
        safe_execute(
            "INSERT OR IGNORE INTO circles (user_id, name) VALUES (?, ?)",
            current_user()["id"], name,
        )
        flash(f"Circle \"{name}\" created.", "success")
    return redirect(url_for("circles"))


@app.post("/circles/<int:circle_id>/add")
@login_required
def add_to_circle(circle_id):
    if not revival_ready():
        return redirect(url_for("home"))
    circle = circle_by_id(circle_id)
    if not circle or circle["user_id"] != current_user()["id"]:
        abort(404)
    username = request.form.get("username", "").strip().lstrip("@")
    person = safe_first(
        "SELECT id, username, display_name FROM users WHERE username=? COLLATE NOCASE",
        username,
    )
    if not person:
        flash("No account by that handle.", "error")
    elif person["id"] == current_user()["id"]:
        flash("You are not a circle; you are the person holding it.", "error")
    elif safe_first("SELECT 1 FROM circle_members WHERE circle_id=? AND user_id=?",
                    circle["id"], person["id"]):
        flash(f"{person['display_name']} is already in {circle['name']}.", "error")
    else:
        safe_execute(
            "INSERT OR IGNORE INTO circle_members (circle_id, user_id) VALUES (?, ?)",
            circle["id"], person["id"],
        )
        flash(f"Added {person['display_name']} to {circle['name']}.", "success")
    return redirect(url_for("circles"))


@app.post("/circles/<int:circle_id>/remove/<int:user_id>")
@login_required
def remove_from_circle(circle_id, user_id):
    if not revival_ready():
        return redirect(url_for("home"))
    circle = circle_by_id(circle_id)
    if not circle or circle["user_id"] != current_user()["id"]:
        abort(404)
    safe_execute(
        "DELETE FROM circle_members WHERE circle_id=? AND user_id=?",
        circle["id"], user_id,
    )
    flash("Removed from the circle.", "success")
    return redirect(url_for("circles"))


@app.post("/circles/<int:circle_id>/delete")
@login_required
def delete_circle(circle_id):
    if not revival_ready():
        return redirect(url_for("home"))
    circle = circle_by_id(circle_id)
    if not circle or circle["user_id"] != current_user()["id"]:
        abort(404)
    # Posts shared with this circle were addressed to a group that is going away.
    # They are not deleted; they become "only me", the honest reading of a share
    # whose audience no longer exists.
    safe_execute(
        "UPDATE posts SET audience='private', circle_id=NULL WHERE circle_id=?",
        circle["id"],
    )
    safe_execute("DELETE FROM circles WHERE id=?", circle["id"])
    flash("Circle deleted. Posts shared with it are now visible only to you.", "success")
    return redirect(url_for("circles"))


# Collections ------------------------------------------------------------------

@app.route("/collections")
@login_required
def collections():
    if not revival_ready():
        return redirect(url_for("home"))
    user = current_user()
    return render_template(
        "collections.html",
        collections=collection_rows(user["id"], user["id"]),
        max_name=MAX_COLLECTION_NAME,
        max_description=MAX_COLLECTION_DESCRIPTION,
    )


@app.post("/collections/create")
@login_required
def create_collection():
    if not revival_ready():
        return redirect(url_for("home"))
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not 1 <= len(name) <= MAX_COLLECTION_NAME:
        flash(f"A collection needs a name of 1-{MAX_COLLECTION_NAME} characters.", "error")
    elif len(description) > MAX_COLLECTION_DESCRIPTION:
        flash("That description is too long.", "error")
    else:
        safe_execute(
            "INSERT OR IGNORE INTO collections (user_id, name, description)"
            " VALUES (?, ?, ?)",
            current_user()["id"], name, description or None,
        )
        flash(f"Collection \"{name}\" created. Pick it when you write a post.", "success")
    return redirect(url_for("collections"))


@app.route("/collections/<int:collection_id>")
def collection(collection_id):
    if not revival_ready():
        abort(404)
    row = collection_by_id(collection_id)
    if not row:
        abort(404)
    owner = first("SELECT * FROM users WHERE id=?", row["user_id"])
    if not owner or owner.get("deleted_at"):
        abort(404)
    clause, params = visibility_sql(session.get("user_db_id") or 0)
    posts = fetch_posts(
        f"WHERE {clause} AND posts.collection_id=?",
        tuple(params + [collection_id]), order="posts.id DESC",
    )
    return render_template(
        "collection.html", collection=row, owner=owner, posts=posts,
    )


@app.post("/collections/<int:collection_id>/delete")
@login_required
def delete_collection(collection_id):
    if not revival_ready():
        return redirect(url_for("home"))
    row = collection_by_id(collection_id)
    if not row or row["user_id"] != current_user()["id"]:
        abort(404)
    safe_execute("UPDATE posts SET collection_id=NULL WHERE collection_id=?", collection_id)
    safe_execute("DELETE FROM collections WHERE id=?", collection_id)
    flash("Collection deleted. Its posts are still on your profile.", "success")
    return redirect(url_for("collections"))


# Communities -------------------------------------------------------------------

@app.route("/communities")
def communities():
    if not revival_ready():
        return render_template("communities.html", communities=[], needs_migration=True)
    viewer = current_user()
    return render_template(
        "communities.html",
        communities=community_rows(viewer["id"] if viewer else 0),
        needs_migration=False,
        max_name=MAX_COMMUNITY_NAME,
        max_description=MAX_COMMUNITY_DESCRIPTION,
    )


@app.post("/communities/create")
@login_required
def create_community():
    if not revival_ready():
        return redirect(url_for("home"))
    name = request.form.get("name", "").strip()
    slug = request.form.get("slug", "").strip().lower()
    description = request.form.get("description", "").strip()
    if not 1 <= len(name) <= MAX_COMMUNITY_NAME:
        flash(f"A community needs a name of 1-{MAX_COMMUNITY_NAME} characters.", "error")
    elif not re.fullmatch(r"[a-z0-9-]{3,40}", slug):
        flash("The address can be 3-40 lowercase letters, numbers or hyphens.", "error")
    elif community_by_slug(slug):
        flash("That community address is taken.", "error")
    elif len(description) > MAX_COMMUNITY_DESCRIPTION:
        flash("That description is too long.", "error")
    else:
        execute(
            "INSERT INTO communities (slug, name, description, owner_id)"
            " VALUES (?, ?, ?, ?)",
            slug, name, description or None, current_user()["id"],
        )
        created = first("SELECT last_insert_rowid() AS id")
        if created:
            safe_execute(
                "INSERT OR IGNORE INTO community_members (community_id, user_id, role)"
                " VALUES (?, ?, 'owner')",
                created["id"], current_user()["id"],
            )
        flash(f"Community \"{name}\" created.", "success")
        return redirect(url_for("community", slug=slug))
    return redirect(url_for("communities"))


@app.route("/c/<slug>")
def community(slug):
    if not revival_ready():
        abort(404)
    row = community_by_slug(slug)
    if not row:
        abort(404)
    owner = first("SELECT * FROM users WHERE id=?", row["owner_id"])
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    membership = community_membership(row["id"], viewer_id)
    clause, params = visibility_sql(viewer_id)
    posts = fetch_posts(
        f"WHERE {clause} AND posts.community_id=?",
        tuple(params + [row["id"]]), order="posts.id DESC", limit=40,
    )
    member_rows = safe_query("""
        SELECT users.id, users.username, users.display_name, users.profile_picture,
               community_members.role, community_members.joined_at
        FROM community_members JOIN users ON users.id = community_members.user_id
        WHERE community_members.community_id=?
        ORDER BY community_members.joined_at LIMIT 60
    """, row["id"])
    return render_template(
        "community.html", community=row, owner=owner, posts=posts,
        membership=membership, members=member_rows,
        is_community_owner=bool(viewer and row["owner_id"] == viewer["id"]),
        can_manage_members=bool(membership and membership["role"] in ("owner", "moderator")),
    )


@app.post("/c/<slug>/join")
@login_required
def join_community(slug):
    if not revival_ready():
        return redirect(url_for("home"))
    row = community_by_slug(slug)
    if not row:
        abort(404)
    safe_execute(
        "INSERT OR IGNORE INTO community_members (community_id, user_id, role)"
        " VALUES (?, ?, 'member')",
        row["id"], current_user()["id"],
    )
    flash(f"Joined {row['name']}.", "success")
    return redirect(url_for("community", slug=slug))


@app.post("/c/<slug>/leave")
@login_required
def leave_community(slug):
    if not revival_ready():
        return redirect(url_for("home"))
    row = community_by_slug(slug)
    if not row:
        abort(404)
    if row["owner_id"] == current_user()["id"]:
        flash("The owner cannot leave the community; delete it instead.", "error")
    else:
        safe_execute(
            "DELETE FROM community_members WHERE community_id=? AND user_id=?",
            row["id"], current_user()["id"],
        )
        flash(f"Left {row['name']}.", "success")
    return redirect(url_for("community", slug=slug))


# Events ------------------------------------------------------------------------

@app.route("/events")
def events():
    if not revival_ready():
        return render_template("events.html", events=[], needs_migration=True)
    return render_template(
        "events.html", events=event_rows(), needs_migration=False,
        max_title=MAX_EVENT_TITLE, max_description=MAX_EVENT_DESCRIPTION,
        max_location=MAX_EVENT_LOCATION,
    )


@app.route("/events/new", methods=["GET", "POST"])
@login_required
def new_event():
    if not revival_ready():
        return redirect(url_for("home"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        starts = request.form.get("starts_at", "").strip().replace("T", " ")
        if not 1 <= len(title) <= MAX_EVENT_TITLE:
            flash("Give the event a title.", "error")
        elif not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", starts):
            flash("Pick a date and time for the event.", "error")
        else:
            execute(
                "INSERT INTO events (owner_id, title, description, starts_at, location)"
                " VALUES (?, ?, ?, ?, ?)",
                current_user()["id"], title, description or None, starts,
                location or None,
            )
            created = first("SELECT last_insert_rowid() AS id")
            if created:
                safe_execute(
                    "INSERT OR IGNORE INTO event_attendees (event_id, user_id, status)"
                    " VALUES (?, ?, 'going')",
                    created["id"], current_user()["id"],
                )
                flash("Event created.", "success")
                return redirect(url_for("event", event_id=created["id"]))
    return render_template(
        "event_editor.html", max_title=MAX_EVENT_TITLE,
        max_description=MAX_EVENT_DESCRIPTION, max_location=MAX_EVENT_LOCATION,
    )


@app.route("/events/<int:event_id>")
def event(event_id):
    if not revival_ready():
        abort(404)
    row = event_by_id(event_id)
    if not row:
        abort(404)
    owner = first("SELECT * FROM users WHERE id=?", row["owner_id"])
    viewer = current_user()
    clause, params = visibility_sql(viewer["id"] if viewer else 0)
    posts = fetch_posts(
        f"WHERE {clause} AND posts.event_id=?",
        tuple(params + [event_id]), order="posts.id DESC", limit=20,
    )
    attendees = safe_query("""
        SELECT users.username, users.display_name, users.profile_picture,
               event_attendees.status
        FROM event_attendees JOIN users ON users.id = event_attendees.user_id
        WHERE event_attendees.event_id=?
        ORDER BY event_attendees.updated_at
    """, event_id)
    return render_template(
        "event.html", event=row, owner=owner, posts=posts, attendees=attendees,
        attendance=event_attendance(event_id, viewer["id"] if viewer else 0),
    )


@app.post("/events/<int:event_id>/rsvp")
@login_required
def rsvp_event(event_id):
    if not revival_ready():
        return redirect(url_for("home"))
    row = event_by_id(event_id)
    if not row:
        abort(404)
    status = request.form.get("status", "going")
    if status not in ("going", "maybe", "no"):
        status = "going"
    safe_execute(
        "INSERT INTO event_attendees (event_id, user_id, status)"
        " VALUES (?, ?, ?)"
        " ON CONFLICT(event_id, user_id) DO UPDATE SET status=excluded.status,"
        " updated_at=datetime('now')",
        event_id, current_user()["id"], status,
    )
    return redirect(url_for("event", event_id=event_id))


# Notifications ------------------------------------------------------------------

@app.route("/notifications")
@login_required
def notifications():
    if not revival_ready():
        flash("Notifications need the newest database migration.", "error")
        return redirect(url_for("home"))
    user = current_user()
    rows = notification_rows(user["id"])
    return render_template(
        "notifications.html", notifications=rows,
        notification_text=notification_text,
        notification_url=notification_url,
    )


@app.post("/notifications/read")
@login_required
def read_notifications():
    if not revival_ready():
        return redirect(url_for("home"))
    safe_execute(
        "UPDATE notifications SET read_at=datetime('now')"
        " WHERE user_id=? AND read_at IS NULL",
        current_user()["id"],
    )
    flash("All caught up.", "success")
    return redirect(url_for("notifications"))


# Search, tags, discovery ---------------------------------------------------------

def like_pattern(value):
    """A LIKE pattern that cannot be widened by a % or _ in the query."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@app.route("/search")
def search():
    """Posts, people and comments in one answer - the hole G+ never had."""
    query_text = request.args.get("q", "").strip()[:80]
    posts = []
    people = []
    comments = []
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    if query_text:
        pattern = like_pattern(query_text)
        clause, params = visibility_sql()
        posts = fetch_posts(
            f"WHERE {clause} AND (posts.title LIKE ? ESCAPE '\\'"
            f" OR posts.content LIKE ? ESCAPE '\\')",
            tuple(params + [pattern, pattern]),
            order="posts.id DESC", limit=30,
        )
        people = safe_query(
            "SELECT id, username, display_name, profile_picture, bio, nickname,"
            " (SELECT COUNT(*) FROM follows WHERE followed_id=users.id) AS follower_count,"
            " (SELECT COUNT(*) FROM follows mine WHERE mine.follower_id=?"
            "   AND mine.followed_id=users.id) AS viewer_follows"
            " FROM users WHERE deleted_at IS NULL AND (username LIKE ? ESCAPE '\\'"
            " OR display_name LIKE ? ESCAPE '\\' OR nickname LIKE ? ESCAPE '\\')"
            " ORDER BY follower_count DESC LIMIT 20",
            viewer_id, pattern, pattern, pattern,
        ) if gplus_schema() else safe_query(
            "SELECT id, username, display_name, profile_picture, bio,"
            " (SELECT COUNT(*) FROM follows WHERE followed_id=users.id) AS follower_count,"
            " (SELECT COUNT(*) FROM follows mine WHERE mine.follower_id=?"
            "   AND mine.followed_id=users.id) AS viewer_follows"
            " FROM users WHERE deleted_at IS NULL AND (username LIKE ? ESCAPE '\\'"
            " OR display_name LIKE ? ESCAPE '\\')"
            " ORDER BY follower_count DESC LIMIT 20",
            viewer_id, pattern, pattern,
        )
        if gplus_schema():
            comments = safe_query(
                "SELECT comments.*, users.username, users.display_name,"
                " posts.title AS post_title, posts.public_id AS post_public_id"
                " FROM comments JOIN users ON users.id = comments.user_id"
                " JOIN posts ON posts.id = comments.post_id"
                f" WHERE ({clause.replace('posts.', 'posts.')}) AND posts.status='published'"
                " AND comments.content LIKE ? ESCAPE '\\'"
                " ORDER BY comments.id DESC LIMIT 20",
                *(params + [pattern]),
            )
    return render_template(
        "search.html", q=query_text, posts=posts, people=people, comments=comments,
    )


@app.route("/tag/<tag>")
def tag(tag):
    tag = (tag or "").strip().lower()[:MAX_FEED_TAG]
    if not re.fullmatch(r"[a-z0-9_]{1,40}", tag):
        abort(404)
    clause, params = visibility_sql()
    posts = fetch_posts(
        f"WHERE {clause} AND posts.id IN (SELECT post_id FROM post_tags WHERE tag=?)",
        tuple(params + [tag]), order="posts.id DESC", limit=40,
    ) if gplus_schema() else []
    return render_template("tag.html", tag=tag, posts=posts)


@app.route("/explore")
def explore():
    """G+'s "What's Hot": what the site is actually paying attention to."""
    clause, params = visibility_sql()
    if gplus_schema():
        engagement = (
            "(COALESCE((SELECT SUM(value) FROM post_votes WHERE post_id=posts.id), 0)"
            " + 3 * (SELECT COUNT(*) FROM comments WHERE post_id=posts.id)"
            " + 4 * (SELECT COUNT(*) FROM shares WHERE post_id=posts.id)"
            " + 2 * (SELECT COUNT(*) FROM post_votes WHERE post_id=posts.id AND value=1))"
        )
        order = f"{engagement} DESC, posts.id DESC"
        where = f"WHERE {clause} AND posts.created_at >= datetime('now', '-14 days')"
    else:
        order = ("COALESCE((SELECT SUM(value) FROM post_votes WHERE post_id=posts.id), 0)"
                 " DESC, posts.id DESC")
        where = "WHERE " + clause
    posts = fetch_posts(
        where, tuple(params), order=order, limit=30,
    )
    return render_template("explore.html", posts=posts, tags=top_tags(20),
                           people=people_suggestions(8))


def people_suggestions(limit=12):
    """Accounts to follow: mutuals first, then the most-followed strangers.

    A local site does not have G+'s contact graph, so follows-of-follows is the
    honest signal it does have - and it is what made G+'s "Find people" useful.
    """
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    if gplus_schema():
        return safe_query(f"""
            SELECT users.id, users.username, users.display_name, users.profile_picture,
                   users.bio, users.tagline,
                   (SELECT COUNT(*) FROM follows f WHERE f.followed_id=users.id)
                       AS follower_count,
                   (SELECT COUNT(*) FROM follows mutual
                     WHERE mutual.follower_id=users.id AND mutual.followed_id=?
                       AND mutual.followed_id IS NOT NULL) AS they_follow_me,
                   (SELECT COUNT(*) FROM follows mine
                     WHERE mine.follower_id=? AND mine.followed_id=users.id)
                       AS i_follow
            FROM users
            WHERE users.deleted_at IS NULL AND users.id<>?
              AND users.username <> ? COLLATE NOCASE
              AND users.id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id=?)
              AND users.id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id=?)
              AND users.id NOT IN (SELECT followed_id FROM follows WHERE follower_id=?)
            ORDER BY they_follow_me DESC, follower_count DESC, users.id DESC
            LIMIT {int(limit)}
        """, viewer_id, viewer_id, viewer_id, moderation_username(),
             viewer_id, viewer_id, viewer_id)
    return safe_query(f"""
        SELECT users.id, users.username, users.display_name, users.profile_picture,
               users.bio,
               (SELECT COUNT(*) FROM follows f WHERE f.followed_id=users.id)
                   AS follower_count,
               (SELECT COUNT(*) FROM follows mine
                 WHERE mine.follower_id=? AND mine.followed_id=users.id) AS i_follow
        FROM users WHERE users.deleted_at IS NULL AND users.id<>?
          AND users.id NOT IN (SELECT followed_id FROM follows WHERE follower_id=?)
        ORDER BY follower_count DESC, users.id DESC LIMIT {int(limit)}
    """, viewer_id, viewer_id, viewer_id)


@app.route("/people")
def people():
    viewer = current_user()
    return render_template(
        "people.html", people=people_suggestions(30),
        following=(follow_list(viewer["id"], "following", viewer["id"], 200)
                   if viewer else []),
    )


@app.route("/profile/<username>/photos")
def photos(username):
    user = profile_user(username)
    # One row per picture, so the grid does not care how many posts they came in.
    rows = []
    for item in photo_posts_of(user["id"]):
        for image in post_image_rows(item["id"]):
            rows.append({"post": item, "image": image})
    tagged_posts = photo_posts_of(user["id"], tagged=True)
    for item in tagged_posts:
        item["gallery"] = post_image_rows(item["id"])
    state = viewer_follow_state(user)
    return render_template(
        "photos.html", user=user, rows=rows, tagged_posts=tagged_posts,
        state=state,
        albums=albums_for(user["id"], state["viewer_id"]),
        max_album_name=MAX_ALBUM_NAME,
        max_album_description=MAX_ALBUM_DESCRIPTION,
    )


# Post and comment actions ---------------------------------------------------------

def post_row(post_id):
    rows = fetch_posts("WHERE posts.id=?", (post_id,))
    return rows[0] if rows else None


def comment_row(comment_id):
    return first("""
        SELECT comments.*, posts.public_id AS post_public_id,
               posts.user_id AS post_user_id, posts.locked AS post_locked
        FROM comments JOIN posts ON posts.id = comments.post_id
        WHERE comments.id=?
    """, comment_id)


@app.post("/post/<int:post_id>/share")
@login_required
def share_post(post_id):
    """Reshare: a new post in your stream quoting the original.

    Stored as a real post row with ``share_of`` set, so it reaches the feed,
    profiles and pagination through the same path as everything else - and the
    original is quoted rather than copied.
    """
    if not revival_ready():
        return redirect(url_for("home"))
    item = post_row(post_id)
    if not item or not may_view(item):
        abort(404)
    body = request.form.get("body", "").strip()
    if len(body) > MAX_SHARE_BODY:
        flash(f"A share note can be {MAX_SHARE_BODY} characters or fewer.", "error")
        return redirect(post_path(post_id))
    user = current_user()
    audience = request.form.get("audience", "public")
    if audience not in ("public", "private"):
        audience = "public"
    execute(
        "INSERT INTO posts (title, content, status, user_id, category, public_id,"
        " share_of, audience) VALUES (?, ?, 'published', ?, ?, ?, ?, ?)",
        item["title"], body, user["id"], post_category_for(user["username"]),
        generate_post_public_id(), item["id"], audience,
    )
    created = first("SELECT last_insert_rowid() AS id")
    if not created:
        return redirect(post_path(post_id))
    safe_execute(
        "INSERT INTO shares (post_id, user_id, post_id_created) VALUES (?, ?, ?)",
        item["id"], user["id"], created["id"],
    )
    notify(item["user_id"], "share", user["id"], item["id"])
    notify_mentions(body, user, created["id"])
    store_post_tags(created["id"], body)
    flash("Shared to your stream.", "success")
    return redirect(post_path(created["id"]))


@app.post("/post/<int:post_id>/pin")
@login_required
def pin_post(post_id):
    item = post_row(post_id)
    if not item:
        abort(404)
    if not can_manage_post(item):
        flash("Only the author can pin a post.", "error")
        return redirect(post_path(post_id))
    safe_execute(
        "UPDATE posts SET pinned=CASE WHEN pinned=1 THEN 0 ELSE 1 END WHERE id=?",
        post_id,
    )
    flash("Pin changed.", "success")
    return redirect(post_path(post_id))


@app.post("/post/<int:post_id>/lock")
@login_required
def lock_post(post_id):
    item = post_row(post_id)
    if not item:
        abort(404)
    if not can_manage_post(item):
        flash("Only the author can lock a post.", "error")
        return redirect(post_path(post_id))
    safe_execute(
        "UPDATE posts SET locked=CASE WHEN locked=1 THEN 0 ELSE 1 END WHERE id=?",
        post_id,
    )
    flash("Comments are now " + ("open" if item.get("locked") else "closed") + ".", "success")
    return redirect(post_path(post_id))


@app.post("/post/<int:post_id>/mute")
@login_required
def mute_post(post_id):
    if not revival_ready():
        return redirect(url_for("home"))
    user = current_user()
    muted = safe_first(
        "SELECT 1 FROM post_mutes WHERE post_id=? AND user_id=?", post_id, user["id"]
    )
    if muted:
        safe_execute("DELETE FROM post_mutes WHERE post_id=? AND user_id=?", post_id, user["id"])
        flash("Notifications for this post are back on.", "success")
    else:
        safe_execute("INSERT OR IGNORE INTO post_mutes (post_id, user_id) VALUES (?, ?)",
                     post_id, user["id"])
        flash("You will not be notified about this post again.", "success")
    return redirect(request.referrer or post_path(post_id))


@app.post("/post/<int:post_id>/report")
@login_required
def report_post(post_id):
    item = post_row(post_id)
    if not item:
        abort(404)
    if not revival_ready():
        return redirect(url_for("home"))
    reason = request.form.get("reason", "").strip()[:MAX_REPORT_REASON]
    if len(reason) < 3:
        flash("Say what is wrong with the post.", "error")
    else:
        safe_execute(
            "INSERT INTO reports (reporter_id, kind, post_id, target_user_id, reason)"
            " VALUES (?, 'post', ?, ?, ?)",
            current_user()["id"], post_id, item.get("user_id"), reason,
        )
        flash("Reported. An admin will look at it.", "success")
    return redirect(post_path(post_id))


@app.post("/comment/<int:comment_id>/vote")
@login_required
def vote_comment(comment_id):
    """+1 a comment; pressing it again takes the +1 back."""
    if not revival_ready():
        return redirect(url_for("home"))
    comment = comment_row(comment_id)
    if not comment:
        abort(404)
    user = current_user()
    existing = safe_first(
        "SELECT 1 FROM comment_votes WHERE comment_id=? AND user_id=?",
        comment_id, user["id"],
    )
    if existing:
        safe_execute("DELETE FROM comment_votes WHERE comment_id=? AND user_id=?",
                     comment_id, user["id"])
    else:
        safe_execute(
            "INSERT OR IGNORE INTO comment_votes (comment_id, user_id) VALUES (?, ?)",
            comment_id, user["id"],
        )
        notify(comment["user_id"], "comment_like", user["id"],
               comment["post_id"], comment_id)
    return redirect(request.referrer or post_path(comment["post_id"]) + f"#comment-{comment_id}")


@app.post("/comment/<int:comment_id>/edit")
@login_required
def edit_comment(comment_id):
    comment = comment_row(comment_id)
    if not comment:
        abort(404)
    user = current_user()
    if comment["user_id"] != user["id"]:
        flash("You can only edit your own comments.", "error")
        return redirect(post_path(comment["post_id"]) + f"#comment-{comment_id}")
    content = request.form.get("content", "").strip()
    if not content:
        flash("A comment cannot be empty.", "error")
    elif len(content) > 2000:
        flash("Your comment is too long.", "error")
    else:
        execute("UPDATE comments SET content=? WHERE id=?", content, comment_id)
        notify_mentions(content, user, comment["post_id"], comment_id)
        flash("Comment edited.", "success")
    return redirect(post_path(comment["post_id"]) + f"#comment-{comment_id}")


@app.post("/comment/<int:comment_id>/delete")
@login_required
def remove_comment(comment_id):
    """Delete a comment: its author, the post's author, or an admin.

    G+ let the person whose post it was clear their own thread; before this the
    only person who could delete a comment was the admin.
    """
    comment = comment_row(comment_id)
    if not comment:
        abort(404)
    user = current_user()
    allowed = (
        comment["user_id"] == user["id"]
        or comment["post_user_id"] == user["id"]
        or is_admin()
    )
    if not allowed:
        flash("You cannot delete that comment.", "error")
    else:
        safe_execute(
            "DELETE FROM comment_votes WHERE comment_id IN"
            " (SELECT id FROM comments WHERE id=? OR parent_id=?)",
            comment_id, comment_id,
        )
        execute("DELETE FROM comments WHERE id=?", comment_id)
        flash("Comment deleted.", "success")
    return redirect(post_path(comment["post_id"]) + "#comments")


@app.post("/comment/<int:comment_id>/report")
@login_required
def report_comment(comment_id):
    comment = comment_row(comment_id)
    if not comment:
        abort(404)
    if not revival_ready():
        return redirect(url_for("home"))
    reason = request.form.get("reason", "").strip()[:MAX_REPORT_REASON]
    if len(reason) < 3:
        flash("Say what is wrong with the comment.", "error")
    else:
        safe_execute(
            "INSERT INTO reports (reporter_id, kind, comment_id, target_user_id, reason)"
            " VALUES (?, 'comment', ?, ?, ?)",
            current_user()["id"], comment_id, comment["user_id"], reason,
        )
        flash("Reported. An admin will look at it.", "success")
    return redirect(post_path(comment["post_id"]) + f"#comment-{comment_id}")


@app.post("/profile/<username>/block")
@login_required
def block_user(username):
    if not revival_ready():
        return redirect(url_for("home"))
    target = profile_user(username)
    viewer = current_user()
    if target["id"] == viewer["id"]:
        flash("You cannot block yourself.", "error")
        return redirect(url_for("profile", username=username))
    existing = safe_first(
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?",
        viewer["id"], target["id"],
    )
    if existing:
        safe_execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?",
                     viewer["id"], target["id"])
        flash(f"Unblocked {target['display_name']}.", "success")
    else:
        safe_execute("INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)",
                     viewer["id"], target["id"])
        # A block ends the relationship in both directions, the way G+'s did.
        execute("DELETE FROM follows WHERE (follower_id=? AND followed_id=?)"
                " OR (follower_id=? AND followed_id=?)",
                viewer["id"], target["id"], target["id"], viewer["id"])
        flash(f"Blocked {target['display_name']}. You will not see each other.", "success")
    return redirect(url_for("profile", username=username))


@app.route("/post/<int:post_id>/ripples")
def ripples(post_id):
    """Ripples: how one post travelled - +1s, reshares and the people behind them.

    The original was an animation of the share graph; this is the same facts as
    a readable page, which is what a small site can honestly support.
    """
    item = post_row(post_id)
    if not item or not may_view(item):
        abort(404)
    return render_template(
        "ripples.html", post=item, voters=voters_of(post_id, 1, 100),
        dislikers=voters_of(post_id, -1, 100), shares=shares_of(post_id),
        comments=comment_threads(post_id, session.get("user_db_id") or 0),
    )


@app.route("/hover/<username>")
def hovercard(username):
    """The little profile card G+ showed when a name was hovered."""
    user = profile_user(username)
    state = viewer_follow_state(user)
    return render_template(
        "_hovercard.html", user=user, socials=social_links_of(user), **state
    )


# Account data export --------------------------------------------------------------

@app.route("/settings/export")
@login_required
def export_account():
    """A Takeout-shaped download of everything this account wrote."""
    user = current_user()
    posts = safe_query("SELECT * FROM posts WHERE user_id=? ORDER BY id", user["id"])
    comments = safe_query(
        "SELECT comments.*, posts.title AS post_title FROM comments"
        " JOIN posts ON posts.id = comments.post_id WHERE comments.user_id=?",
        user["id"],
    )
    payload = {
        "exported_at": utcnow().strftime(DB_TIME_FORMAT) + " UTC",
        "account": {
            "user_id": user.get("user_id"),
            "username": user.get("username"),
            "display_name": user.get("display_name"),
            "nickname": user.get("nickname"),
            "tagline": user.get("tagline"),
            "bio": user.get("bio"),
            "created_at": user.get("created_at"),
        },
        "posts": [
            {**row, "images": [image["filename"] for image in post_image_rows(row["id"])]}
            for row in posts
        ],
        "comments": comments,
        "followers": [row["username"] for row in safe_query(
            "SELECT users.username FROM follows JOIN users ON users.id=follows.follower_id"
            " WHERE follows.followed_id=?", user["id"])],
        "following": [row["username"] for row in safe_query(
            "SELECT users.username FROM follows JOIN users ON users.id=follows.followed_id"
            " WHERE follows.follower_id=?", user["id"])],
        "circles": [
            {**circle, "members": [person["username"]
                                    for person in circle_member_rows(circle["id"])]}
            for circle in circle_rows(user["id"])
        ] if gplus_schema() else [],
        "collections": collection_rows(user["id"], user["id"]),
    }
    body = json.dumps(payload, indent=2, default=str)
    return Response(
        body, mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{user["username"]}-google-plus-export.json"',
            "Cache-Control": "no-store",
        },
    )


# Muting, notification preferences and email --------------------------------------

@app.post("/profile/<username>/mute")
@login_required
def mute_user(username):
    """Mute or unmute a person: their posts leave your streams, nothing else."""
    if not gplus2_schema():
        flash("Muting needs the newest database migration. Run `npm run db:remote`.", "error")
        return redirect(url_for("profile", username=username))
    target = profile_user(username)
    viewer = current_user()
    if target["id"] == viewer["id"]:
        flash("You cannot mute yourself.", "error")
        return redirect(url_for("profile", username=username))
    if is_muted(viewer["id"], target["id"]):
        safe_execute(
            "DELETE FROM user_mutes WHERE muter_id=? AND muted_id=?",
            viewer["id"], target["id"],
        )
        flash(f"Unmuted {target['display_name']}. Their posts are back in your streams.", "success")
    else:
        safe_execute(
            "INSERT OR IGNORE INTO user_mutes (muter_id, muted_id) VALUES (?, ?)",
            viewer["id"], target["id"],
        )
        flash(f"Muted {target['display_name']}. Their posts will not appear in your streams.", "success")
    return redirect(safe_next(
        request.form.get("next"), url_for("profile", username=username)
    ))


@app.route("/settings/notifications", methods=["GET", "POST"])
@login_required
def notification_settings():
    """Per-kind notification switches, an optional digest address, muted people."""
    if not gplus2_schema():
        flash("Notification settings need the newest database migration. Run `npm run db:remote`.", "error")
        return redirect(url_for("settings"))
    user = current_user()
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        digest = 1 if request.form.get("email_digest") else 0
        prefs = {
            kind: bool(request.form.get("notify_" + kind))
            for kind in NOTIFICATION_KINDS
        }
        if len(email) > MAX_EMAIL:
            flash(f"An email address can be {MAX_EMAIL} characters or fewer.", "error")
        elif email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("That does not look like an email address.", "error")
        else:
            safe_execute(
                "UPDATE users SET email=?, email_digest=?, notification_prefs=? WHERE id=?",
                email or None, digest, json.dumps(prefs), user["id"],
            )
            flash("Notification settings saved.", "success")
            return redirect(url_for("notification_settings"))
    user = current_user()
    return render_template(
        "notification_settings.html",
        prefs=notification_prefs(user),
        kinds=NOTIFICATION_KINDS,
        labels=NOTIFICATION_LABELS,
        email_ready=email_configured(),
        muted=muted_people(user["id"]),
        max_email=MAX_EMAIL,
    )


@app.post("/admin/email/flush")
@admin_required
def admin_flush_email():
    """Send the queued digest emails, in one batch, from the admin panel."""
    sent, message = flush_emails()
    flash(message, "success" if sent else "error")
    return redirect(url_for("admin") + "#email")


# Pages ----------------------------------------------------------------------------

def page_post_count(page_id):
    row = safe_first(
        "SELECT COUNT(*) AS total FROM posts"
        " WHERE page_id=? AND status='published'", page_id,
    )
    return int(row["total"]) if row else 0


@app.route("/pages")
def pages():
    viewer = current_user()
    return render_template(
        "pages.html",
        pages=page_rows(),
        my_pages=pages_for(viewer["id"]) if viewer else [],
        needs_migration=not gplus2_schema(),
        max_name=MAX_PAGE_NAME,
        max_tagline=MAX_PAGE_TAGLINE,
        max_about=MAX_PAGE_ABOUT,
    )


@app.post("/pages/create")
@login_required
def create_page():
    if not gplus2_schema():
        flash("Pages need the newest database migration. Run `npm run db:remote`.", "error")
        return redirect(url_for("pages"))
    user = current_user()
    name = request.form.get("name", "").strip()
    slug = request.form.get("slug", "").strip().lower()
    tagline = request.form.get("tagline", "").strip()
    about = request.form.get("about", "").strip()
    if not 1 <= len(name) <= MAX_PAGE_NAME:
        flash(f"A page needs a name of 1-{MAX_PAGE_NAME} characters.", "error")
        return redirect(url_for("pages"))
    if not re.fullmatch(r"[a-z0-9-]{3,40}", slug):
        flash("The page address can be 3-40 lowercase letters, numbers or hyphens.", "error")
        return redirect(url_for("pages"))
    if page_by_slug(slug):
        flash("That page address is taken.", "error")
        return redirect(url_for("pages"))
    if len(tagline) > MAX_PAGE_TAGLINE or len(about) > MAX_PAGE_ABOUT:
        flash("The tagline or About text is too long.", "error")
        return redirect(url_for("pages"))
    avatar, avatar_error = save_image_upload(request.files.get("avatar"))
    banner, banner_error = save_image_upload(request.files.get("banner"))
    if avatar_error or banner_error:
        for stored in (avatar, banner):
            delete_upload(stored)
        flash(avatar_error or banner_error, "error")
        return redirect(url_for("pages"))
    execute(
        "INSERT INTO pages (slug, name, tagline, about, avatar, banner, owner_id)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        slug, name, tagline or None, about or None, avatar, banner, user["id"],
    )
    created = first("SELECT last_insert_rowid() AS id")
    if not created:
        for stored in (avatar, banner):
            delete_upload(stored)
        flash("The page could not be created.", "error")
        return redirect(url_for("pages"))
    safe_execute(
        "INSERT OR IGNORE INTO page_managers (page_id, user_id, role)"
        " VALUES (?, ?, 'owner')",
        created["id"], user["id"],
    )
    flash(f"Page \"{name}\" created.", "success")
    return redirect(url_for("page_detail", slug=slug))


@app.route("/pages/<slug>")
def page_detail(slug):
    if not gplus2_schema():
        abort(404)
    row = page_by_slug(slug)
    if not row:
        abort(404)
    owner = first("SELECT * FROM users WHERE id=?", row["owner_id"])
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    return render_template(
        "page.html",
        page=row,
        owner=owner,
        posts=page_posts(row, viewer_id),
        managers=page_managers_rows(row["id"]),
        can_manage=can_manage_page(row, viewer),
        is_owner=bool(viewer and row["owner_id"] == viewer["id"]),
        post_count=page_post_count(row["id"]),
    )


@app.route("/pages/<slug>/edit", methods=["GET", "POST"])
@login_required
def edit_page(slug):
    if not gplus2_schema():
        abort(404)
    row = page_by_slug(slug)
    if not row:
        abort(404)
    if not can_manage_page(row, current_user()):
        flash("Only a page's managers can edit it.", "error")
        return redirect(url_for("page_detail", slug=slug))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        tagline = request.form.get("tagline", "").strip()
        about = request.form.get("about", "").strip()
        if not 1 <= len(name) <= MAX_PAGE_NAME:
            flash(f"A page needs a name of 1-{MAX_PAGE_NAME} characters.", "error")
        elif len(tagline) > MAX_PAGE_TAGLINE or len(about) > MAX_PAGE_ABOUT:
            flash("The tagline or About text is too long.", "error")
        else:
            avatar, avatar_error = save_image_upload(request.files.get("avatar"))
            banner, banner_error = save_image_upload(request.files.get("banner"))
            if avatar_error or banner_error:
                for stored in (avatar, banner):
                    delete_upload(stored)
                flash(avatar_error or banner_error, "error")
            else:
                fields = {"name": name, "tagline": tagline or None, "about": about or None}
                removed = []
                if avatar:
                    fields["avatar"] = avatar
                    removed.append(row["avatar"])
                elif request.form.get("remove_avatar"):
                    fields["avatar"] = None
                    removed.append(row["avatar"])
                if banner:
                    fields["banner"] = banner
                    removed.append(row["banner"])
                elif request.form.get("remove_banner"):
                    fields["banner"] = None
                    removed.append(row["banner"])
                assignments = ", ".join(f"{column}=?" for column in fields)
                execute(
                    f"UPDATE pages SET {assignments} WHERE id=?",
                    *fields.values(), row["id"],
                )
                for filename in removed:
                    delete_upload(filename)
                flash("Page updated.", "success")
                return redirect(url_for("page_detail", slug=row["slug"]))
    return render_template(
        "page_editor.html", page=row,
        max_name=MAX_PAGE_NAME, max_tagline=MAX_PAGE_TAGLINE,
        max_about=MAX_PAGE_ABOUT,
    )


@app.post("/pages/<slug>/delete")
@login_required
def delete_page(slug):
    if not gplus2_schema():
        abort(404)
    row = page_by_slug(slug)
    if not row:
        abort(404)
    if row["owner_id"] != current_user()["id"]:
        flash("Only the page's owner can delete it.", "error")
        return redirect(url_for("page_detail", slug=slug))
    safe_execute("UPDATE posts SET page_id=NULL WHERE page_id=?", row["id"])
    for filename in (row["avatar"], row["banner"]):
        delete_upload(filename)
    safe_execute("DELETE FROM pages WHERE id=?", row["id"])
    flash(f"Deleted the page \"{row['name']}\". Its posts are still on their authors' profiles.", "success")
    return redirect(url_for("pages"))


@app.post("/pages/<slug>/managers")
@login_required
def add_page_manager(slug):
    if not gplus2_schema():
        abort(404)
    row = page_by_slug(slug)
    if not row:
        abort(404)
    if row["owner_id"] != current_user()["id"]:
        flash("Only the page's owner can add managers.", "error")
        return redirect(url_for("page_detail", slug=slug))
    username = request.form.get("username", "").strip().lstrip("@")
    person = first(
        "SELECT id, display_name, deleted_at FROM users WHERE username=? COLLATE NOCASE",
        username,
    )
    if not person or person.get("deleted_at"):
        flash("There is no account by that name.", "error")
    else:
        safe_execute(
            "INSERT OR IGNORE INTO page_managers (page_id, user_id, role)"
            " VALUES (?, ?, 'manager')",
            row["id"], person["id"],
        )
        flash(f"{person['display_name']} can now post as {row['name']}.", "success")
    return redirect(url_for("page_detail", slug=slug))


@app.post("/pages/<slug>/managers/<int:user_id>/remove")
@login_required
def remove_page_manager(slug, user_id):
    if not gplus2_schema():
        abort(404)
    row = page_by_slug(slug)
    if not row:
        abort(404)
    viewer = current_user()
    if row["owner_id"] != viewer["id"] and user_id != viewer["id"]:
        flash("Only the page's owner can remove managers.", "error")
        return redirect(url_for("page_detail", slug=slug))
    if user_id == row["owner_id"]:
        flash("The owner cannot be removed from their own page.", "error")
    else:
        safe_execute(
            "DELETE FROM page_managers WHERE page_id=? AND user_id=?",
            row["id"], user_id,
        )
        flash("Manager removed.", "success")
    return redirect(url_for("page_detail", slug=slug))


# Albums --------------------------------------------------------------------------

@app.post("/albums/create")
@login_required
def create_album():
    if not gplus2_schema():
        flash("Albums need the newest database migration. Run `npm run db:remote`.", "error")
        return redirect(url_for("photos", username=current_user()["username"]))
    user = current_user()
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not 1 <= len(name) <= MAX_ALBUM_NAME:
        flash(f"An album needs a name of 1-{MAX_ALBUM_NAME} characters.", "error")
    elif len(description) > MAX_ALBUM_DESCRIPTION:
        flash("That album description is too long.", "error")
    elif safe_first(
        "SELECT 1 FROM albums WHERE user_id=? AND name=? COLLATE NOCASE",
        user["id"], name,
    ):
        flash("You already have an album with that name.", "error")
    else:
        safe_execute(
            "INSERT INTO albums (user_id, name, description) VALUES (?, ?, ?)",
            user["id"], name, description or None,
        )
        flash(f"Album \"{name}\" created.", "success")
    return redirect(url_for("photos", username=user["username"]))


@app.route("/albums/<int:album_id>")
def album(album_id):
    if not gplus2_schema():
        abort(404)
    row = album_by_id(album_id)
    if not row:
        abort(404)
    viewer = current_user()
    viewer_id = viewer["id"] if viewer else 0
    owner = first("SELECT * FROM users WHERE id=?", row["user_id"])
    posts = album_posts(album_id)
    if row["user_id"] != viewer_id and not posts:
        abort(404)
    return render_template(
        "album.html", album=row, owner=owner, posts=posts,
        is_owner=bool(viewer and row["user_id"] == viewer_id),
    )


@app.post("/albums/<int:album_id>/delete")
@login_required
def delete_album(album_id):
    if not gplus2_schema():
        abort(404)
    row = album_by_id(album_id)
    if not row:
        abort(404)
    if row["user_id"] != current_user()["id"]:
        flash("You can only delete your own albums.", "error")
        return redirect(url_for("album", album_id=album_id))
    safe_execute("DELETE FROM albums WHERE id=?", album_id)
    flash("Album deleted. Its posts are still on your profile.", "success")
    return redirect(url_for("photos", username=current_user()["username"]))


@app.post("/post/<int:post_id>/albums")
@login_required
def set_post_albums(post_id):
    """Put one photo post in (or take it out of) the author's named albums."""
    if not gplus2_schema():
        abort(404)
    item = post_row(post_id)
    if not item:
        abort(404)
    user = current_user()
    if not can_manage_post(item):
        flash("You can only file your own posts into albums.", "error")
        return redirect(post_path(post_id))
    wanted = set()
    for value in request.form.getlist("album_ids"):
        if value.isdigit():
            wanted.add(int(value))
    owned = {row["id"] for row in albums_for(user["id"], user["id"])}
    safe_execute("DELETE FROM album_posts WHERE post_id=?", post_id)
    for album_id in wanted & owned:
        safe_execute(
            "INSERT OR IGNORE INTO album_posts (album_id, post_id) VALUES (?, ?)",
            album_id, post_id,
        )
    flash("Albums updated.", "success")
    return redirect(post_path(post_id))


# Hangouts ------------------------------------------------------------------------

def hangout_room_from_form():
    return jitsi_room_name()


@app.route("/hangouts")
def hangouts():
    return render_template(
        "hangouts.html", hangouts=hangout_rows(),
        needs_migration=not gplus2_schema(),
        max_title=MAX_HANGOUT_TITLE,
    )


@app.post("/hangouts/create")
@login_required
def create_hangout():
    if not gplus2_schema():
        flash("Hangouts need the newest database migration. Run `npm run db:remote`.", "error")
        return redirect(url_for("hangouts"))
    title = request.form.get("title", "").strip()
    kind = request.form.get("kind", "hangout")
    if kind not in ("hangout", "onair"):
        kind = "hangout"
    youtube_url = request.form.get("youtube_url", "").strip()
    if kind == "onair" and youtube_url and not youtube_id(youtube_url):
        flash("That does not look like a YouTube link.", "error")
        return redirect(url_for("hangouts"))
    if not 1 <= len(title) <= MAX_HANGOUT_TITLE:
        flash(f"Give the hangout a title of 1-{MAX_HANGOUT_TITLE} characters.", "error")
        return redirect(url_for("hangouts"))
    room = jitsi_room_name()
    safe_execute(
        "INSERT INTO hangouts (owner_id, title, room, kind, youtube_url)"
        " VALUES (?, ?, ?, ?, ?)",
        current_user()["id"], title, room, kind, youtube_url or None,
    )
    created = safe_first("SELECT id FROM hangouts WHERE room=?", room)
    if not created:
        flash("The hangout could not be created.", "error")
        return redirect(url_for("hangouts"))
    flash("Your hangout is live. Share the page or invite people from a profile.", "success")
    return redirect(url_for("hangout", room=room))


@app.route("/hangouts/<room>")
def hangout(room):
    if not gplus2_schema():
        abort(404)
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,80}", room or ""):
        abort(404)
    row = hangout_by_room(room)
    if not row:
        abort(404)
    owner = first("SELECT * FROM users WHERE id=?", row["owner_id"])
    viewer = current_user()
    return render_template(
        "hangout.html", hangout=row, owner=owner,
        is_owner=bool(viewer and viewer["id"] == row["owner_id"]),
        video_id=youtube_id(row.get("youtube_url")),
        jitsi_url=f"https://meet.jit.si/{row['room']}",
    )


@app.post("/hangouts/<room>/end")
@login_required
def end_hangout(room):
    if not gplus2_schema():
        abort(404)
    row = hangout_by_room(room)
    if not row:
        abort(404)
    if row["owner_id"] != current_user()["id"]:
        flash("Only the person who started it can end a hangout.", "error")
        return redirect(url_for("hangout", room=room))
    safe_execute(
        "UPDATE hangouts SET ended_at=datetime('now') WHERE id=?", row["id"]
    )
    flash("The hangout has ended.", "success")
    return redirect(url_for("hangouts"))


# Sparks --------------------------------------------------------------------------

@app.route("/sparks")
def sparks():
    return render_template(
        "sparks.html", sparks=spark_rows(),
        needs_migration=not gplus2_schema(),
        max_name=MAX_SPARK_NAME, max_description=MAX_SPARK_DESCRIPTION,
    )


@app.post("/sparks/create")
@login_required
def create_spark():
    if not gplus2_schema():
        flash("Sparks need the newest database migration. Run `npm run db:remote`.", "error")
        return redirect(url_for("sparks"))
    name = request.form.get("name", "").strip()
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    description = request.form.get("description", "").strip()
    if not 1 <= len(name) <= MAX_SPARK_NAME:
        flash(f"A spark needs a name of 1-{MAX_SPARK_NAME} characters.", "error")
    elif not slug:
        flash("Use at least one letter or number in the name.", "error")
    elif spark_by_slug(slug):
        flash("There is already a spark with that name.", "error")
    elif len(description) > MAX_SPARK_DESCRIPTION:
        flash("That description is too long.", "error")
    else:
        safe_execute(
            "INSERT INTO sparks (name, slug, description, created_by) VALUES (?, ?, ?, ?)",
            name, slug, description or None, current_user()["id"],
        )
        flash(f"Spark \"{name}\" created. Add the first link to it.", "success")
        return redirect(url_for("spark", slug=slug))
    return redirect(url_for("sparks"))


@app.route("/sparks/<slug>")
def spark(slug):
    if not gplus2_schema():
        abort(404)
    row = spark_by_slug(slug)
    if not row:
        abort(404)
    return render_template(
        "spark.html", spark=row, links=spark_link_rows(row["id"]),
        max_note=MAX_SPARK_NOTE,
    )


@app.post("/sparks/<slug>/add")
@login_required
def add_spark_link(slug):
    if not gplus2_schema():
        abort(404)
    row = spark_by_slug(slug)
    if not row:
        abort(404)
    url = request.form.get("url", "").strip()
    note = request.form.get("note", "").strip()
    if url and not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    if not is_public_url(url):
        flash("Paste an http(s) address on a public website.", "error")
    elif safe_first("SELECT 1 FROM spark_links WHERE spark_id=? AND url=?", row["id"], url):
        flash("That link is already in this spark.", "error")
    elif len(note) > MAX_SPARK_NOTE:
        flash(f"A note can be {MAX_SPARK_NOTE} characters or fewer.", "error")
    else:
        ensure_link_preview(url)
        safe_execute(
            "INSERT INTO spark_links (spark_id, url, note, added_by) VALUES (?, ?, ?, ?)",
            row["id"], url, note or None, current_user()["id"],
        )
        flash("Link added.", "success")
    return redirect(url_for("spark", slug=slug))


# Community roles and embeds ------------------------------------------------------

@app.post("/c/<slug>/members/<int:user_id>/role")
@login_required
def community_member_role(slug, user_id):
    if not revival_ready():
        return redirect(url_for("home"))
    row = community_by_slug(slug)
    if not row:
        abort(404)
    if row["owner_id"] != current_user()["id"]:
        flash("Only the community owner can change roles.", "error")
        return redirect(url_for("community", slug=slug))
    role = request.form.get("role", "member")
    if role not in ("moderator", "member"):
        role = "member"
    if user_id == row["owner_id"]:
        flash("The owner's role cannot be changed.", "error")
    else:
        safe_execute(
            "UPDATE community_members SET role=? WHERE community_id=? AND user_id=?",
            role, row["id"], user_id,
        )
        flash("Role updated.", "success")
    return redirect(url_for("community", slug=slug))


@app.post("/c/<slug>/members/<int:user_id>/remove")
@login_required
def community_remove_member(slug, user_id):
    if not revival_ready():
        return redirect(url_for("home"))
    row = community_by_slug(slug)
    if not row:
        abort(404)
    viewer = current_user()
    membership = community_membership(row["id"], viewer["id"])
    if not membership or membership["role"] not in ("owner", "moderator"):
        flash("Only the owner or a moderator can remove members.", "error")
        return redirect(url_for("community", slug=slug))
    if user_id == row["owner_id"]:
        flash("The owner cannot be removed.", "error")
        return redirect(url_for("community", slug=slug))
    target = community_membership(row["id"], user_id)
    if not target:
        flash("That account is not a member.", "error")
    elif membership["role"] == "moderator" and target["role"] != "member":
        flash("Moderators can only remove members.", "error")
    else:
        safe_execute(
            "DELETE FROM community_members WHERE community_id=? AND user_id=?",
            row["id"], user_id,
        )
        flash("Member removed.", "success")
    return redirect(url_for("community", slug=slug))


@app.post("/c/<slug>/delete")
@login_required
def delete_community(slug):
    if not revival_ready():
        return redirect(url_for("home"))
    row = community_by_slug(slug)
    if not row:
        abort(404)
    if row["owner_id"] != current_user()["id"]:
        flash("Only the owner can delete a community.", "error")
        return redirect(url_for("community", slug=slug))
    safe_execute("UPDATE posts SET community_id=NULL WHERE community_id=?", row["id"])
    safe_execute("DELETE FROM communities WHERE id=?", row["id"])
    flash(f"Deleted the community \"{row['name']}\". Its posts are still on their authors' profiles.", "success")
    return redirect(url_for("communities"))


@app.route("/post/<int:post_id>/embed")
def embed_post(post_id):
    """A bare page for an <iframe>: the post, nothing around it."""
    rows = fetch_posts("WHERE posts.id=?", (post_id,))
    if not rows:
        abort(404)
    item = rows[0]
    if not may_view(item):
        abort(404)
    return render_template(
        "embed_post.html", post=item,
        images=post_image_rows(item["id"]),
        embed=embed_for(item.get("link_url")),
    )


# Admin: reports and verification ------------------------------------------------

@app.post("/admin/reports/<int:report_id>/resolve")
@admin_required
def resolve_report(report_id):
    if not revival_ready():
        return redirect(url_for("admin"))
    safe_execute(
        "UPDATE reports SET resolved_at=datetime('now'), resolved_by=?"
        " WHERE id=? AND resolved_at IS NULL",
        actor_name(current_user()), report_id,
    )
    flash("Report closed.", "success")
    return redirect(url_for("admin") + "#reports")


@app.post("/admin/users/<int:user_id>/verify")
@admin_required
def verify_user(user_id):
    """Toggle the G+ check mark on an account."""
    if not revival_ready():
        return redirect(url_for("admin"))
    target = first("SELECT id, display_name FROM users WHERE id=?", user_id)
    if not target:
        abort(404)
    safe_execute(
        "UPDATE users SET verified=CASE WHEN verified=1 THEN 0 ELSE 1 END WHERE id=?",
        user_id,
    )
    flash("Verification changed.", "success")
    return redirect(url_for("admin") + "#users")


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(error):
    flash(f"That file is too large. Images must be {MAX_IMAGE_BYTES // 1000} KB or smaller.", "error")
    return redirect(request.referrer or url_for("home"))


# Shown when a request dies in a way Flask never sees. The runtime raises its
# own CpuLimitExceeded, which is not an Exception subclass, so it sails straight
# past Flask's error handling and out of the Worker - which the outside world
# sees as Cloudflare's bare "error code: 1101" page. Catching BaseException here
# gives the visitor a sentence instead of that, and puts the traceback in the
# Worker log (wrangler tail) where it can be read.
FALLBACK_ERROR_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Something went wrong</title>
<style>
  body { font: 16px/1.6 system-ui, sans-serif; margin: 0; padding: 3rem 1.5rem;
         background: #14161c; color: #e8eaf0; text-align: center; }
  .card { max-width: 34rem; margin: 0 auto; background: #1c1f27;
          border: 1px solid #2b3040; border-radius: 12px; padding: 2rem; }
  h1 { font-size: 1.35rem; margin: 0 0 .75rem; }
  p { color: #b6bccb; margin: .5rem 0 1.25rem; }
  a { color: #8ab4ff; }
</style></head>
<body><div class="card">
<h1>The server could not finish that request</h1>
<p>Sorry - something went wrong on our side. Please try again. If you were
uploading a picture, a smaller image will go through.</p>
<p><a href="/">Back to the feed</a></p>
</div></body></html>"""


class UnhandledErrorPage:
    """Last-chance WSGI wrapper: log the crash, answer with a readable page."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def _report(self, exc, environ):
        try:
            app.logger.error(
                "Unhandled error on %s %s: %s: %s",
                environ.get("REQUEST_METHOD"), environ.get("PATH_INFO"),
                type(exc).__name__, exc, exc_info=True,
            )
        except Exception:  # logging must never mask the original failure
            pass

    def __call__(self, environ, start_response):
        try:
            # Materialise the response inside the guard: iterating it later is
            # what actually runs the view for some response types.
            result = list(self.wsgi_app(environ, start_response))
        except BaseException as exc:
            self._report(exc, environ)
            body = FALLBACK_ERROR_PAGE.encode()
            headers = [("Content-Type", "text/html; charset=utf-8"),
                       ("Content-Length", str(len(body))),
                       ("Cache-Control", "no-store")]
            try:
                start_response("500 Internal Server Error", headers)
            except Exception:
                # The status line was already sent, so there is nothing left to
                # say; end the body rather than emitting a second header block.
                return []
            return [body]
        return result


Default = wsgi.entrypoint(UnhandledErrorPage(app))
