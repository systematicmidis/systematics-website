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
import mimetypes
import os
import re
import secrets
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
# from the per-image check instead of a bare 413.
MAX_IMAGE_BYTES = 1_800_000
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
POST_STATUSES = ("published", "draft")
# Every post lands in exactly one category: owner accounts write to "systematics",
# everybody else to "community". Both are public; the split just keeps the owner's
# posts separable from the community feed (and filterable on the home page).
POST_CATEGORIES = ("community", "systematics")
POST_CATEGORY_LABELS = {
    "community": "Community posts",
    "systematics": "Systematics posts",
}

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


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "is_admin": is_admin(),
    }


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_db_id"):
            flash("You need to be logged in to do that.", "error")
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


def valid_username(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,24}", value))


def post_category_for(username):
    """Owner accounts post to the Systematics feed, everyone else to Community."""
    return "systematics" if is_owner_username(username) else "community"


def can_manage_post(item):
    """True for a post's own author and for site owners/admins."""
    if is_admin():
        return True
    user = current_user()
    return bool(user and item and item["user_id"] == user["id"])


def fetch_posts(where="", params=(), limit=None):
    """Post rows plus author, score, comment count and the viewer's own vote.

    The viewer id is bound first (0 for anonymous visitors, which matches no row),
    so ``params`` follows the WHERE clause placeholders.
    """
    viewer = session.get("user_db_id") or 0
    sql = f"""
        SELECT posts.*,
               users.username AS author_username,
               users.display_name AS author_display_name,
               users.profile_picture AS author_picture,
               COALESCE((SELECT SUM(value) FROM post_votes WHERE post_id=posts.id), 0) AS score,
               (SELECT COUNT(*) FROM comments WHERE post_id=posts.id) AS comment_count,
               (SELECT value FROM post_votes WHERE post_id=posts.id AND user_id=?) AS my_vote,
               link_previews.title AS link_title,
               link_previews.description AS link_description,
               link_previews.image AS link_image,
               link_previews.site AS link_site
        FROM posts
        LEFT JOIN users ON users.id = posts.user_id
        LEFT JOIN link_previews ON link_previews.url = posts.link_url
        {where}
        ORDER BY posts.created_at DESC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return query(sql, viewer, *params)


def category_counts():
    """Published post totals per feed, for the home page tabs."""
    counts = {name: 0 for name in POST_CATEGORIES}
    for row in query(
        "SELECT category, COUNT(*) AS total FROM posts"
        " WHERE status='published' GROUP BY category"
    ):
        counts[row["category"]] = row["total"]
    counts["all"] = sum(counts.values())
    return counts


def comment_threads(post_id):
    """A post's comments as top-level rows, each carrying its ``replies`` list."""
    rows = query("""
        SELECT comments.*, users.id AS author_id,
               users.user_id AS public_user_id,
               users.username, users.display_name, users.profile_picture
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE comments.post_id=?
        ORDER BY comments.created_at ASC
    """, post_id)
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


# Link cards -----------------------------------------------------------------

META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
ATTR_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"""
)
TITLE_TAG_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"'\]\[]+", re.IGNORECASE)


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
    execute(
        "INSERT INTO uploads (filename, content_type, size, data) VALUES (?, ?, ?, ?)",
        filename, content_type, len(data), to_js(data),
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
    """The feed. ``?category=community`` / ``?category=systematics`` filters it."""
    category = request.args.get("category", "")
    if category not in POST_CATEGORIES:
        category = ""
    where = "WHERE posts.status='published'"
    params = []
    if category:
        where += " AND posts.category=?"
        params.append(category)
    return render_template(
        "index.html",
        posts=fetch_posts(where, tuple(params)),
        category=category,
        category_labels=POST_CATEGORY_LABELS,
        counts=category_counts(),
    )


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post(post_id):
    rows = fetch_posts("WHERE posts.id=?", (post_id,))
    if not rows:
        abort(404)
    item = rows[0]
    # Drafts are unlisted: the author and site owners can open them to review,
    # everybody else gets a 404.
    if item["status"] != "published" and not can_manage_post(item):
        abort(404)

    if request.method == "POST":
        if not session.get("user_db_id"):
            flash("Log in or create an account to comment.", "error")
            return redirect(url_for("login", next=url_for("post", post_id=post_id) + "#comments"))
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
        else:
            execute(
                "INSERT INTO comments (post_id, user_id, content, parent_id) VALUES (?, ?, ?, ?)",
                item["id"], session["user_db_id"], content, parent["id"] if parent else None,
            )
            return redirect(url_for("post", post_id=post_id) + anchor)

    return render_template(
        "post.html",
        post=item,
        comments=comment_threads(item["id"]),
        can_manage=can_manage_post(item),
    )


@app.post("/post/<int:post_id>/vote")
def vote_post(post_id):
    """Like (+1) or dislike (-1) a post; repeating the same vote clears it."""
    item = first("SELECT id FROM posts WHERE id=? AND status='published'", post_id)
    if not item:
        abort(404)
    if not session.get("user_db_id"):
        flash("Sign in to like or dislike posts.", "error")
        return redirect(url_for("login", next=url_for("post", post_id=post_id)))
    try:
        value = int(request.form.get("value", "0"))
    except ValueError:
        value = 0
    if value not in (-1, 1):
        value = 0
    user_id = session["user_db_id"]
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
    return redirect(request.referrer or url_for("post", post_id=post_id))


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_post():
    """Any signed-in account can post; the category follows from the account."""
    user = current_user()
    if request.method == "POST":
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
    )


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    item = first("SELECT * FROM posts WHERE id=?", post_id)
    if not item:
        abort(404)
    if not can_manage_post(item):
        flash("You can only edit your own posts.", "error")
        return redirect(url_for("post", post_id=post_id))
    if request.method == "POST":
        target = save_post(item)
        if target:
            flash("Post updated.", "success")
            return redirect(target)
    return render_template(
        "post_editor.html",
        post=item,
        cancel_url=url_for("post", post_id=post_id),
        can_choose_status=is_admin(),
        can_choose_category=is_admin(),
        default_category=item["category"],
    )


@app.post("/post/<int:post_id>/delete")
@login_required
def delete_post(post_id):
    item = first("SELECT * FROM posts WHERE id=?", post_id)
    if not item:
        abort(404)
    if not can_manage_post(item):
        flash("You can only delete your own posts.", "error")
        return redirect(url_for("post", post_id=post_id))
    execute("DELETE FROM post_votes WHERE post_id=?", post_id)
    execute("DELETE FROM comments WHERE post_id=?", post_id)
    execute("DELETE FROM posts WHERE id=?", post_id)
    flash("Post deleted.", "success")
    return redirect(url_for("admin") if is_admin() else url_for("home"))


def save_post(item=None):
    """Create or update a post from the editor form; returns where to go next."""
    user = current_user()
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
    # A link in the body gets a card under the post. The card is fetched right here,
    # once, and cached in D1 so no page render ever waits on another website.
    link_url = extract_post_link(content, request.host.split(":")[0])
    if link_url:
        ensure_link_preview(link_url)
    if item is None:
        execute(
            "INSERT INTO posts (title, content, status, user_id, category, link_url)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            title, content, status, user["id"], category, link_url or None,
        )
        created = first("SELECT last_insert_rowid() AS id")
        return url_for("post", post_id=created["id"]) if created else url_for("home")
    execute(
        "UPDATE posts SET title=?, content=?, status=?, category=?, link_url=? WHERE id=?",
        title, content, status, category, link_url or None, item["id"],
    )
    return url_for("post", post_id=item["id"])


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
            public_id = secrets.token_hex(8)
            picture, picture_error = save_image_upload(request.files.get("profile_picture"))
            if picture_error:
                flash(picture_error, "error")
                return render_template("register.html")
            execute("""
                INSERT INTO users (user_id, username, display_name, password_hash, profile_picture)
                VALUES (?, ?, ?, ?, ?)
            """, public_id, username, display_name,
                 hash_password(password), picture)
            user = first("SELECT * FROM users WHERE user_id=?", public_id)
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
    if request.method == "POST":
        remember = bool(request.form.get("remember"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
        if user and verify_password(user["password_hash"], password):
            session.clear()
            session["user_db_id"] = user["id"]
            # "Remember me" is the only thing that gives the cookie an expiry
            # date; without it the browser drops it when it closes. session.clear()
            # above also discarded any previous choice, so this is set fresh each
            # sign-in rather than inherited from the last one.
            if request.form.get("remember"):
                session.permanent = True
            return redirect(request.form.get("next") or url_for("home"))
        flash("Invalid username or password.", "error")
    return render_template(
        "login.html",
        next_url=next_url,
        remember=remember,
        remember_days=REMEMBER_SESSION_DAYS,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/profile/<username>")
def profile(username):
    user = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
    if not user:
        abort(404)
    comments = query("""
        SELECT comments.content, comments.created_at, posts.id AS post_id, posts.title
        FROM comments JOIN posts ON posts.id=comments.post_id
        WHERE comments.user_id=? AND posts.status='published'
        ORDER BY comments.created_at DESC LIMIT 20
    """, user["id"])
    posts = fetch_posts(
        "WHERE posts.user_id=? AND posts.status='published'", (user["id"],)
    )
    return render_template("profile.html", user=user, posts=posts, comments=comments)


@app.route("/settings/profile", methods=["GET", "POST"])
@login_required
def profile_settings():
    user = current_user()
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        bio = request.form.get("bio", "").strip()
        if not 1 <= len(display_name) <= 40:
            flash("Display name must be 1–40 characters.", "error")
        elif len(bio) > MAX_BIO_LENGTH:
            flash(f"Your bio must be {MAX_BIO_LENGTH} characters or fewer.", "error")
        else:
            picture, picture_error = save_image_upload(request.files.get("profile_picture"))
            banner, banner_error = save_image_upload(request.files.get("banner"))
            upload_error = picture_error or banner_error
            if upload_error:
                # Do not keep whichever half of the upload did succeed.
                for stored in (picture, banner):
                    delete_upload(stored)
                flash(upload_error, "error")
            else:
                fields = {"display_name": display_name, "bio": bio or None}
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
    return render_template("profile_settings.html", user=user, max_bio_length=MAX_BIO_LENGTH)


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
        SELECT posts.*, users.username AS author_username
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
    return render_template("admin.html", posts=posts, comments=comments, users=users)


@app.post("/admin/delete-comment/<int:comment_id>")
@admin_required
def delete_comment(comment_id):
    execute("DELETE FROM comments WHERE id=?", comment_id)
    return redirect(url_for("admin") + "#comments")


@app.post("/admin/refresh-links")
@admin_required
def admin_refresh_links():
    """Re-fetch the link cards for posts that contain a URL.

    Covers posts written before link cards existed, and refresh is what makes a
    card whose target page was down resolvable later without editing the post.
    """
    rows = query("SELECT id, content FROM posts ORDER BY id DESC")
    checked = cards = 0
    for row in rows:
        if checked >= MAX_LINK_REFRESH_PER_RUN:
            break
        url = extract_post_link(row["content"], request.host.split(":")[0])
        if not url:
            continue
        checked += 1
        if ensure_link_preview(url, force=True):
            cards += 1
        execute("UPDATE posts SET link_url=? WHERE id=?", url, row["id"])
    if not checked:
        flash("No posts with links to refresh.", "error")
    else:
        flash(f"Checked {checked} link{'s' if checked != 1 else ''}, "
              f"rebuilt {cards} card{'s' if cards != 1 else ''}.", "success")
    return redirect(url_for("admin") + "#posts")


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(error):
    flash(f"That file is too large. Images must be {MAX_IMAGE_BYTES // 1000} KB or smaller.", "error")
    return redirect(request.referrer or url_for("home"))


Default = wsgi.entrypoint(app)
