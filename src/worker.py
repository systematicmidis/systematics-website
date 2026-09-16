import os
import re
import secrets
import mimetypes
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    abort, flash, Response
)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pyodide.ffi import run_sync
from workers import wsgi


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"

app = Flask(__name__, template_folder=str(TEMPLATE_DIR), static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


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


def current_user():
    uid = session.get("user_db_id")
    if not uid:
        return None
    return first("SELECT * FROM users WHERE id=?", uid)


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "is_admin": bool(session.get("admin")),
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
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def valid_username(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,24}", value))


def save_profile_picture(file):
    if not file or not file.filename:
        return None
    original = secure_filename(file.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return None
    filename = secrets.token_hex(16) + "." + ext
    data = file.read()
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    run_sync(env().BUCKET.put(filename, data, {"httpMetadata": {"contentType": content_type}}))
    return filename


@app.route("/uploads/<filename>")
def uploads(filename):
    if "/" in filename or "\\" in filename or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9]+", filename):
        abort(404)
    obj = run_sync(env().BUCKET.get(filename))
    if obj is None:
        abort(404)
    body = run_sync(obj.body.arrayBuffer())
    body = bytes(body.to_py() if hasattr(body, "to_py") else body)
    content_type = getattr(obj, "httpMetadata", None)
    if content_type is not None:
        content_type = py(content_type)
    mime = content_type.get("contentType") if isinstance(content_type, dict) else None
    mime = mime or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(body, status=200, content_type=mime, headers={"Cache-Control": "public, max-age=31536000, immutable"})


@app.route("/static/<path:path>")
def static_files(path):
    assets = env().ASSETS
    response = run_sync(assets.fetch(f"https://assets.local/static/{path}"))
    body = run_sync(response.bytes())
    return Response(body, status=response.status, headers=response.headers)


@app.route("/")
def home():
    posts = query("SELECT * FROM posts WHERE status='published' ORDER BY created_at DESC")
    return render_template("index.html", posts=posts)


@app.route("/post/<slug>", methods=["GET", "POST"])
def post(slug):
    item = first("SELECT * FROM posts WHERE slug=? AND status='published'", slug)
    if not item:
        abort(404)

    if request.method == "POST":
        if not session.get("user_db_id"):
            flash("Log in or create an account to comment.", "error")
            return redirect(url_for("login", next=url_for("post", slug=slug) + "#comments"))
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
            return redirect(url_for("post", slug=slug) + "#comments")

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
            picture = save_profile_picture(request.files.get("profile_picture"))
            execute("""
                INSERT INTO users (user_id, username, display_name, password_hash, profile_picture)
                VALUES (?, ?, ?, ?, ?)
            """, public_id, username, display_name, generate_password_hash(password), picture)
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
        if user and check_password_hash(user["password_hash"], password):
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
        SELECT comments.content, comments.created_at, posts.title, posts.slug
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
        if not 1 <= len(display_name) <= 40:
            flash("Display name must be 1–40 characters.", "error")
        else:
            picture = save_profile_picture(request.files.get("profile_picture"))
            if picture:
                execute("UPDATE users SET display_name=?, profile_picture=? WHERE id=?", display_name, picture, user["id"])
            else:
                execute("UPDATE users SET display_name=? WHERE id=?", display_name, user["id"])
            flash("Profile updated.", "success")
            return redirect(url_for("profile_settings"))
    return render_template("profile_settings.html", user=user)


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
        slug = request.form.get("slug", "").strip().lower()
        content = request.form.get("content", "").strip()
        status = request.form.get("status", "published")
        if not title or not slug or not content:
            flash("Title, slug, and content are required.", "error")
        elif first("SELECT id FROM posts WHERE slug=?", slug):
            flash("That slug is already being used.", "error")
        else:
            execute("INSERT INTO posts (title, slug, content, status) VALUES (?, ?, ?, ?)", title, slug, content, status)
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
        slug = request.form.get("slug", "").strip().lower()
        content = request.form.get("content", "").strip()
        status = request.form.get("status", "published")
        other = first("SELECT id FROM posts WHERE slug=? AND id<>?", slug, post_id)
        if other:
            flash("That slug is already being used.", "error")
        else:
            execute("UPDATE posts SET title=?, slug=?, content=?, status=? WHERE id=?", title, slug, content, status, post_id)
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


Default = wsgi.entrypoint(app)
