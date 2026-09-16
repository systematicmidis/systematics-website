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
import mimetypes
import os
import re
import secrets
import struct
from functools import wraps
from pathlib import Path

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request,
    session, url_for,
)
from flask.sessions import SecureCookieSessionInterface
from js import Object
from pyodide.ffi import run_sync, to_js as _to_js

try:  # the Worker global scope provides this; plain CPython does not
    from js import crypto as js_crypto
except ImportError:  # pragma: no cover - depends on the runtime
    js_crypto = None
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from workers import wsgi


def to_js(obj):
    """Turn Python dictionaries/lists into plain JavaScript objects."""
    return _to_js(obj, dict_converter=Object.fromEntries)


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

# Profile bios and post statuses.
MAX_BIO_LENGTH = 500
POST_STATUSES = ("published", "draft")

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
    if js_crypto is None:
        raise RuntimeError("WebCrypto is not available")
    subtle = js_crypto.subtle
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
    posts = query("SELECT * FROM posts WHERE status='published' ORDER BY created_at DESC")
    return render_template("index.html", posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post(post_id):
    item = first("SELECT * FROM posts WHERE id=? AND status='published'", post_id)
    if not item:
        abort(404)

    if request.method == "POST":
        if not session.get("user_db_id"):
            flash("Log in or create an account to comment.", "error")
            return redirect(url_for("login", next=url_for("post", post_id=post_id) + "#comments"))
        content = request.form.get("content", "").strip()
        if not content:
            flash("Please enter a comment.", "error")
        elif len(content) > 2000:
            flash("Your comment is too long.", "error")
        else:
            execute(
                "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
                item["id"], session["user_db_id"], content,
            )
            return redirect(url_for("post", post_id=post_id) + "#comments")

    comments = query("""
        SELECT comments.*, users.user_id AS public_user_id,
               users.username, users.display_name, users.profile_picture
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE comments.post_id=?
        ORDER BY comments.created_at ASC
    """, item["id"])
    return render_template("post.html", post=item, comments=comments)


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
            flash("Your account has been created!", "success")
            return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))
    next_url = request.args.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = first("SELECT * FROM users WHERE username=? COLLATE NOCASE", username)
        if user and verify_password(user["password_hash"], password):
            session.clear()
            session["user_db_id"] = user["id"]
            return redirect(request.form.get("next") or url_for("home"))
        flash("Invalid username or password.", "error")
    return render_template("login.html", next_url=next_url)


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
    return render_template("profile.html", user=user, comments=comments)


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
    posts = query("SELECT * FROM posts ORDER BY created_at DESC")
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


@app.route("/admin/new", methods=["GET", "POST"])
@admin_required
def new_post():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        status = request.form.get("status", "published")
        if status not in POST_STATUSES:
            status = "published"
        if not title or not content:
            flash("Title and content are required.", "error")
        else:
            execute("INSERT INTO posts (title, content, status) VALUES (?, ?, ?)", title, content, status)
            return redirect(url_for("admin"))
    return render_template("post_editor.html", post=None)


@app.route("/admin/edit/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    item = first("SELECT * FROM posts WHERE id=?", post_id)
    if not item:
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        status = request.form.get("status", "published")
        if status not in POST_STATUSES:
            status = "published"
        if not title or not content:
            flash("Title and content are required.", "error")
        else:
            execute("UPDATE posts SET title=?, content=?, status=? WHERE id=?", title, content, status, post_id)
            return redirect(url_for("admin"))
    return render_template("post_editor.html", post=item)


@app.post("/admin/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    execute("DELETE FROM comments WHERE post_id=?", post_id)
    execute("DELETE FROM posts WHERE id=?", post_id)
    return redirect(url_for("admin"))


@app.post("/admin/delete-comment/<int:comment_id>")
@admin_required
def delete_comment(comment_id):
    execute("DELETE FROM comments WHERE id=?", comment_id)
    return redirect(url_for("admin") + "#comments")


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(error):
    flash(f"That file is too large. Images must be {MAX_IMAGE_BYTES // 1000} KB or smaller.", "error")
    return redirect(request.referrer or url_for("home"))


Default = wsgi.entrypoint(app)
