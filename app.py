import os
import re
import sqlite3
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, send_from_directory

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DATABASE = os.path.join(os.path.dirname(__file__), "site.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        profile_picture TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        content TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'published',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    if conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO posts (title, slug, content) VALUES (?, ?, ?)",
            ("Welcome to my Black MIDI site!", "welcome",
             "This is my new home for Black MIDI projects, upcoming videos, progress updates, and downloads. More projects are coming soon!")
        )
    conn.commit()
    conn.close()

def current_user():
    uid = session.get("user_db_id")
    if not uid:
        return None
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return user

@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "is_admin": bool(session.get("admin"))
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
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return None
    filename = secrets.token_hex(16) + "." + ext
    file.save(os.path.join(UPLOAD_DIR, filename))
    return filename

@app.route("/uploads/<filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route("/")
def home():
    conn = db()
    posts = conn.execute(
        "SELECT * FROM posts WHERE status='published' ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("index.html", posts=posts)

@app.route("/post/<slug>", methods=["GET", "POST"])
def post(slug):
    conn = db()
    item = conn.execute(
        "SELECT * FROM posts WHERE slug=? AND status='published'", (slug,)
    ).fetchone()
    if not item:
        conn.close()
        abort(404)

    if request.method == "POST":
        if not session.get("user_db_id"):
            conn.close()
            flash("Log in or create an account to comment.", "error")
            return redirect(url_for("login", next=url_for("post", slug=slug) + "#comments"))

        content = request.form.get("content", "").strip()
        if not content:
            flash("Please enter a comment.", "error")
        elif len(content) > 2000:
            flash("Your comment is too long.", "error")
        else:
            conn.execute(
                "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
                (item["id"], session["user_db_id"], content)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("post", slug=slug) + "#comments")

    comments = conn.execute("""
        SELECT comments.*, users.user_id AS public_user_id,
               users.username, users.display_name, users.profile_picture
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE comments.post_id=?
        ORDER BY comments.created_at ASC
    """, (item["id"],)).fetchall()
    conn.close()
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
        else:
            conn = db()
            exists = conn.execute(
                "SELECT id FROM users WHERE username=? COLLATE NOCASE", (username,)
            ).fetchone()
            if exists:
                conn.close()
                flash("That username is already taken.", "error")
            else:
                public_id = secrets.token_hex(8)
                picture = save_profile_picture(request.files.get("profile_picture"))
                conn.execute("""
                    INSERT INTO users (user_id, username, display_name, password_hash, profile_picture)
                    VALUES (?, ?, ?, ?, ?)
                """, (public_id, username, display_name,
                      generate_password_hash(password), picture))
                user_db_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.commit()
                conn.close()
                session.clear()
                session["user_db_id"] = user_db_id
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
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone()
        conn.close()

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
    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
    ).fetchone()
    if not user:
        conn.close()
        abort(404)
    comments = conn.execute("""
        SELECT comments.content, comments.created_at, posts.title, posts.slug
        FROM comments JOIN posts ON posts.id=comments.post_id
        WHERE comments.user_id=? AND posts.status='published'
        ORDER BY comments.created_at DESC LIMIT 20
    """, (user["id"],)).fetchall()
    conn.close()
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
            conn = db()
            if picture:
                conn.execute(
                    "UPDATE users SET display_name=?, profile_picture=? WHERE id=?",
                    (display_name, picture, user["id"])
                )
            else:
                conn.execute(
                    "UPDATE users SET display_name=? WHERE id=?",
                    (display_name, user["id"])
                )
            conn.commit()
            conn.close()
            flash("Profile updated.", "success")
            return redirect(url_for("profile_settings"))
    return render_template("profile_settings.html", user=user)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
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
    conn = db()
    posts = conn.execute("SELECT * FROM posts ORDER BY created_at DESC").fetchall()
    comments = conn.execute("""
        SELECT comments.*, posts.title AS post_title,
               users.username, users.display_name
        FROM comments
        JOIN posts ON posts.id = comments.post_id
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.created_at DESC
    """).fetchall()
    users = conn.execute(
        "SELECT * FROM users ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
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
        else:
            conn = db()
            try:
                conn.execute(
                    "INSERT INTO posts (title, slug, content, status) VALUES (?, ?, ?, ?)",
                    (title, slug, content, status)
                )
                conn.commit()
                conn.close()
                return redirect(url_for("admin"))
            except sqlite3.IntegrityError:
                conn.close()
                flash("That slug is already being used.", "error")
    return render_template("post_editor.html", post=None)

@app.route("/admin/edit/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    conn = db()
    item = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        slug = request.form.get("slug", "").strip().lower()
        content = request.form.get("content", "").strip()
        status = request.form.get("status", "published")
        try:
            conn.execute(
                "UPDATE posts SET title=?, slug=?, content=?, status=? WHERE id=?",
                (title, slug, content, status, post_id)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("admin"))
        except sqlite3.IntegrityError:
            flash("That slug is already being used.", "error")
    conn.close()
    return render_template("post_editor.html", post=item)

@app.post("/admin/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    conn = db()
    conn.execute("DELETE FROM comments WHERE post_id=?", (post_id,))
    conn.execute("DELETE FROM posts WHERE id=?", (post_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))

@app.post("/admin/delete-comment/<int:comment_id>")
@admin_required
def delete_comment(comment_id):
    conn = db()
    conn.execute("DELETE FROM comments WHERE id=?", (comment_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin") + "#comments")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
