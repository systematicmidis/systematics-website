# Systematics Black MIDI site

A small Flask community site (accounts with bios, avatars and custom profile banners, plus
posts, two feeds, likes/dislikes and threaded comments) that runs on **Cloudflare Workers**
using the Python Workers runtime and D1 - and that fits on the **Workers Free plan, with no
payment method on file**. See ["Running free"](#running-free-no-payment-method) for what that
costs and limits.

| Piece | Cloudflare product | Where it lives |
| --- | --- | --- |
| Flask app (routes + Jinja templates) | Python Workers (`workers-py` / `pywrangler`) | `src/worker.py`, `src/templates/` |
| Users (with bios), posts, comments, votes | D1 (SQLite) binding `DB` | `migrations/` |
| Uploaded profile pictures and banners | D1 `uploads` table (BLOB rows) | `migrations/0005_uploads_in_d1.sql` |
| Stylesheets | Workers static assets binding `ASSETS` | `public/static/` |

## Project layout

```
wrangler.jsonc        Worker config: bindings, assets, secrets, compatibility
pyproject.toml        Python dependencies (this is what pywrangler installs)
package.json          Convenience scripts for dev / deploy / database
migrations/*.sql      Numbered D1 migrations (see "Schema changes" below)
src/worker.py         The Flask app that is deployed as the Worker
src/templates/*.html  Jinja templates, bundled with the Worker
public/static/        Static assets served at /static/*
.dev.vars             Local-only secrets (gitignored)
app.py                Original plain-Flask/SQLite version of the app (local only)
```

## Prerequisites

- **Node.js 20+** and npm - `pywrangler` shells out to `npx wrangler`.
- **uv** - the Python toolchain pywrangler uses. Windows:
  `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
  (or `winget install --id=astral-sh.uv`).
- A Cloudflare account, logged in once with `npx wrangler login`.

## One-time setup

```bash
npm install                       # local wrangler (also gives config schema hints)

# 1. Database
npx wrangler d1 list              # already created? reuse it, skip the next line
npx wrangler d1 create systematics-black-midi-db
#    -> copy the printed database_id into wrangler.jsonc (`d1_databases[0].database_id`).
#    This project's database already exists with the id in the checked-in config, so
#    `d1 list` normally shows it and there is nothing to create or paste.

# 2. Production secrets (before the first deploy - see the note below)
npx wrangler secret put SESSION_SECRET    # long random string, e.g. openssl rand -hex 32
npx wrangler secret put ADMIN_PASSWORD    # password for /admin/login

# 3. Create the tables in the remote database
npm run db:remote

# 4. Ship it
npm run deploy                            # -> https://systematics-bm.<you>.workers.dev
```

There is no bucket or storage service to create: uploaded images are rows in the same D1
database, so every resource in this project is on the Workers Free plan. Everything above is
free of charge and needs no credit card - see ["Running free"](#running-free-no-payment-method).

`wrangler.jsonc` declares `secrets.required`, so `deploy` refuses to run until both secrets
exist - that keeps you from shipping the placeholder session key. Because of that, set the
secrets *before* the first `deploy`: `wrangler secret put` offers to create the Worker when it
does not exist yet. (`npx wrangler deploy --secrets-file .env.production` is the one-command
alternative if you would rather upload secrets with the code.)

Then register the `SystematicMIDIS` account on the deployed site straight away - it is the
site owner, and usernames are first-come-first-served.

## Local development

```bash
npm run db:local     # apply pending migrations to the local D1 database
npm run dev          # uv run pywrangler dev -> http://localhost:8787
```

Local D1 (which holds users, posts, comments and uploaded images) is simulated on disk under
`.wrangler/`, and the values in `.dev.vars` are used for `SESSION_SECRET` /
`ADMIN_PASSWORD`. Sign in to the admin area at `/admin/login`.

The first `dev`/`deploy` run downloads the Pyodide build of Flask into `python_modules/`,
so it takes a minute.

## Site owners

Signing in as a **site owner account** unlocks the admin panel automatically - the nav shows
"Manage" and `/admin` works without entering the shared password. Owners are listed in
`OWNER_USERNAMES` (comma separated) in `wrangler.jsonc`; the built-in default is
`SystematicMIDIS`.

Because owner rights attach to the *account*, make sure that username is registered to you
before you share the site - usernames are unique, so whoever registers it first gets the key.

`ADMIN_PASSWORD` at `/admin/login` still works as a fallback when you are not signed in as a
user (for example from a device you do not want to log in on). It is set with
`npx wrangler secret put ADMIN_PASSWORD`.

## Posting, feeds, votes and replies

**Anyone with an account can post.** Signed-in users see "Write" in the nav and a
"Write a post" button on the feed; posts appear immediately (no moderation queue), and the
author can edit or delete their own post from the post page. Site owners can additionally
edit or delete *any* post, keep a post as a draft, and file it into either feed.

**Two feeds.** Every post carries a category, and `/?category=community` or
`/?category=systematics` filters the feed (the tabs on the home page). Regular accounts can
only write to **Community posts** - the category is decided from the author's account, so a
forged `category` form field is ignored (`post_category_for()` in `src/worker.py`). Only
accounts listed in `OWNER_USERNAMES` land in **Systematics posts**, which stays your channel
while the community has its own. Draft posts are unlisted: only their author and site owners
can open `/post/<id>` for them.

The seeded welcome post has no author until an owner account exists, so the first owner to
register claims it (`register()` in `src/worker.py`), and a database that already has the
account is fixed by migration `0006` - which is why the first post on the site is attributed
to `SystematicMIDIS` rather than to "the site".

**Voting.** `▲` / `▼` on any published post write one row per user to `post_votes`, so a
visitor can switch between like and dislike (or click the same button again to clear it).
Signed-out visitors see a "Sign in to vote" link instead. Post scores and comment counts are
computed per request in `fetch_posts()`.

**Threaded comments.** Comments are one level deep: a reply to a reply attaches to the same
parent (`comments.parent_id`), which keeps long threads readable. Deleting a parent comment
leaves its replies as their own top-level comments rather than removing them. Site owners can
delete individual comments from the admin panel.

## Schema changes

The database schema is versioned in `migrations/` and applied with wrangler's D1 migration
runner, which records what has run in a `d1_migrations` table:

```bash
npm run db:local     # uv run pywrangler d1 migrations apply systematics-black-midi-db --local
npm run db:remote    # the same against production D1
```

Add a new numbered file (for example `migrations/0007_add_post_tags.sql`) instead of editing
one that has already been applied. Migrations run in filename order.

## Deploy

```bash
npm run deploy       # uv run pywrangler deploy
```

After a schema change, apply it to the remote database with `npm run db:remote`.
To put the Worker on your own domain, add a `routes` entry to `wrangler.jsonc`:

```jsonc
"routes": [{ "pattern": "example.com", "custom_domain": true }]
```

### Deploying from GitHub

**Use `pywrangler deploy`, not bare `wrangler deploy`.** `pywrangler` runs a `sync` step
first that vendors the Pyodide builds of your `pyproject.toml` dependencies into
`python_modules/`; a plain `npx wrangler deploy` from a fresh clone uploads ~37 KiB of Python
and templates with **no** Flask in it. (Verified with `npx wrangler deploy --dry-run` in a
clean copy.) `python_modules/` is gitignored, so it never arrives via `git clone` - it has to
be generated by the build.

So a Git-connected deploy has to run the Python toolchain:

- **Workers Builds (dashboard Git integration).** Connect the repo under your Worker's
  Settings > Build. Set **Root directory** to the folder holding `wrangler.jsonc` if the
  project is not at the repo root, and note the dashboard Worker name must match `name` in
  `wrangler.jsonc` (`systematics-bm`). The build image is Node-based, so the default deploy
  command (`npx wrangler deploy`) will not vendor Flask - override the commands, for example
  build: `npm install && curl -LsSf https://astral.sh/uv/install.sh | sh && ~/.local/bin/uv run pywrangler sync`,
  deploy: `~/.local/bin/uv run pywrangler deploy`. Python Workers are not a documented
  Workers Builds target, so treat this as something to try, not a supported path.
- **GitHub Actions (what I would actually use).** A workflow that installs uv, runs
  `uv run pywrangler deploy`, and holds `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` as
  repository secrets. Same branch-to-production control, no reliance on the build image.

Either way, `npm run db:remote` is still a manual step you run yourself: builds deploy code,
not database migrations.

## Notes and gotchas

- **`requirements.txt` must not exist.** pywrangler refuses to run while it is present;
  dependencies belong in `pyproject.toml`. (It was deleted in this conversion - `app.py`'s
  dependencies are already listed there.)
- **Password hashing is PBKDF2-HMAC-SHA256 in `src/worker.py`, done by WebCrypto.**
  Pyodide's `hashlib` is built without OpenSSL's key-derivation functions (no
  `pbkdf2_hmac`, no `scrypt`), so Werkzeug's `generate_password_hash` /
  `check_password_hash` raise `AttributeError` inside the Worker - this was the one thing
  that could not be kept API-compatible. The module defines `hash_password` /
  `verify_password`, which derive through `hashlib.pbkdf2_hmac` on plain CPython, through
  the runtime's native `crypto.subtle` PBKDF2 in the Worker, and through a pure-Python
  fallback only if neither exists. Hashes stay in Werkzeug's own
  `pbkdf2:sha256:<iterations>$<salt>$<hash>` format, so rows are readable by `app.py`, and
  each hash records its own iteration count. At `PASSWORD_HASH_ITERATIONS = 100000` a
  derivation measured ~1.7 ms instead of the ~0.35 s the pure-Python path took - which is
  what makes the Free plan viable. Override the count with the `PASSWORD_HASH_ITERATIONS`
  Worker variable (there is a commented example in `wrangler.jsonc`) if you want a
  different work factor.
- **Templates are bundled automatically**: wrangler uploads everything under `src/`, and
  `src/worker.py` probes for the `templates/` directory at startup.
- **Sessions are signed with `SESSION_SECRET`.** Rotating it logs everyone out. Never
  deploy the placeholder value.
- **Posts are addressed by id**: `/post/3`, not `/post/some-slug`. The `slug` column was
dropped in `0003_posts_use_ids.sql`, so old slug URLs now 404. The post editor no longer
  asks for a slug.
- **Bios are optional** and capped at `MAX_BIO_LENGTH` (500 characters) in `src/worker.py`.
  They are edited at `/settings/profile` and shown on the public profile page.
- **Profile banners are optional** (`users.banner`, added in `0004_add_user_banner.sql`).
  A banner is uploaded at `/settings/profile`, stored like an avatar, and rendered as a
  105 px cover image behind the avatar (the `profile-cover` gradient is the default). Replacing
  or clearing one - or uploading a new avatar - deletes the stored image it replaced; ticking
  "Remove my banner" clears it. During sign-up only an avatar can be chosen; the banner is set
  afterwards from `/settings/profile`.
- **Uploads are D1 rows**, not files and not R2 (`0005_uploads_in_d1.sql`): the `uploads`
  table holds the bytes as a BLOB, and `/uploads/<file>` serves them with an immutable
  cache header. D1 caps a row at 2 MB, so images are limited to `MAX_IMAGE_BYTES`
  (1.8 MB) and to png/jpg/jpeg/gif/webp; anything else - or anything larger - is refused
  with a flash message instead of being dropped silently. Browsers cache the images, so a
  page view does not re-read every avatar.
- **Why not R2?** It is the better home for blobs and the free tier is generous, but
  enabling it means completing an R2 subscription checkout, i.e. putting a payment method
  on the account. Everything in this project runs on D1, which does not.
- **Never hold a JavaScript global in a module-level variable.** The first deploy of this
  project returned `error code: 1101` on roughly **half of all requests**, including
  `/static/*`, with `cpuTime` of 0-1 ms - i.e. the Worker died before running any
  application code. `wrangler tail` showed the cause:
  `NoGilError: Attempted to use PyProxy when Python GIL not held`, thrown from
  `python_getattr` inside `preparePython()` at isolate startup. The module had
  `from js import Object` / `from js import crypto` at the top, and the deploy-time snapshot
  carries those live JS proxies, which then fail to rehydrate on isolate start. They are now
  fetched inside the functions that need them (`js_object_from_entries()`,
  `webcrypto_subtle()`); after that change, 100/100 requests and 12/12 cold starts succeeded.
  If you add code that talks to JavaScript, follow the same rule - import it in the function,
  not at the top of the module.
- **Compatibility date**: Python Workers need `compatibility_flags: ["python_workers"]`.
  Bumping `compatibility_date` in `wrangler.jsonc` also bumps the Python version.
- If wrangler complains about an unsupported field (for example `secrets`), update it:
  `npm install wrangler@latest`.

## Running free (no payment method)

The Worker uses only products that are available on the Workers Free plan without billing
details: Workers itself, Workers static assets, D1, Workers Logs (observability), and the
`workers.dev` subdomain. Nothing here needs a card, and typical usage sits far inside the free
quotas:

| Free-plan limit | Value | What it means here |
| --- | --- | --- |
| Requests | 100,000/day | A personal site rarely comes close |
| CPU time | 10 ms/request | The real constraint - see below |
| D1 storage / reads / writes | 5 GB / 5M rows / 100k rows per day | Images count against the 5 GB |
| Worker bundle | 64 MiB uncompressed | This one is ~2.2 MB |

**The 10 ms CPU budget is the thing to watch.** Cloudflare's own guidance is that
server-side rendering and authentication "typically use 10-20 ms", and a Flask app running
in Pyodide measures in that range locally, so free-plan requests sit right at the ceiling.
What was measured on this project (local `pywrangler dev`, wall time per request):

| Request (local `pywrangler dev`) | Cost |
| --- | --- |
| Page render (`/`, `/post/1`) | ~15-25 ms |
| Settings save with no image | ~25 ms |
| Settings save with a 10 KB image | ~70 ms (+~4 ms per KB) |
| ... 100 KB / 400 KB / 1.7 MB image | ~0.32 s / ~1.3 s / ~6.2 s |

Measured on the deployed Worker instead (CPU time from `wrangler tail`), which is the
number that actually matters:

| Deployed behaviour | Result |
| --- | --- |
| Page renders, static assets, `/uploads/*` | 6-32 ms CPU, all served (the runtime allows occasional overshoot) |
| Sign-in (100,000-iteration PBKDF2) | served, no CPU error |
| 10 KB and 100 KB image uploads | served |
| 500 KB and 1.7 MB image uploads | **`error code: 1102`** |

So uploads are the only thing the free plan actually refuses, and the practical ceiling sits
somewhere between 100 KB and 500 KB. Keep avatars and banners small (a few tens of KB), or
resize them in the browser before uploading, and the whole site runs free.

Two consequences:

- Password hashing is no longer the problem: native WebCrypto brought a sign-in down to
  roughly the cost of rendering a page (it used to be ~0.35 s and dominate everything).
- **Image uploads are the expensive part**, because Werkzeug parses the multipart body in
  Python. On the free plan expect uploads to be the first thing to hit
  `Error 1102 - Worker exceeded resource limits` (shown as `exceededCpu` under
  Metrics > Errors); on Workers Paid the 30 s CPU default handles them comfortably.
  Keeping images small helps a lot, and resizing them in the browser before upload would
  help more.

If pages themselves start erroring with 1102, the options are Workers Paid ($5/month, which
also raises the limit via `"limits": { "cpu_ms": 30000 }`), or moving the app to a host that
runs Python natively instead of inside a Worker.

Other free-plan notes:

- Exceeding 100,000 requests in a day returns `Error 1027` until midnight UTC.
- D1 free-tier daily read/write limits pause queries for the rest of the day; storage is the
  sum of all databases on the account.
- R2 stays unused, so there is no bucket to create, no egress bill and no checkout.

## Running the original local-only app

`app.py` is the pre-Cloudflare version (SQLite file + local uploads folder) and is handy
for quick UI work:

```bash
pip install flask werkzeug
python app.py     # http://localhost:5000, database: site.db
```

It predates newer features - it still uses slug URLs, has no bios, no banners and no owner
accounts - and it uses Werkzeug's `generate_password_hash`, so accounts it creates are stored as scrypt
hashes that the Worker cannot verify (Pyodide has no OpenSSL KDFs). Sign-in works one way
only: hashes written by the Worker are readable by `app.py`, not the reverse. Create accounts
through the Worker if you plan to deploy them.
