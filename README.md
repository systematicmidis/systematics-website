# Systematics Black MIDI site

A small Flask community site (accounts with bios, avatars and custom profile banners,
followers, posts, two feeds, likes/dislikes and threaded comments) that runs on **Cloudflare Workers**
using the Python Workers runtime and D1 - and that fits on the **Workers Free plan, with no
payment method on file**. See ["Running free"](#running-free-no-payment-method) for what that
costs and limits.

| Piece | Cloudflare product | Where it lives |
| --- | --- | --- |
| Flask app (routes + Jinja templates) | Python Workers (`workers-py` / `pywrangler`) | `src/worker.py`, `src/templates/` |
| Users (with bios), posts, comments, votes, follows | D1 (SQLite) binding `DB` | `migrations/` |
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

**Link cards.** A post whose body contains a web link gets a card underneath it - the target
page's title, description, image and domain, read from its Open Graph tags, the same tags
Discord and Slack use. A MediaFire file link therefore shows the file name and MediaFire's
file-type icon, with `mediafire.com` at the foot of the card.

The card is fetched **once, when the post is saved**, and cached in the `link_previews` table
(`0007_link_previews.sql`), so rendering a feed or a post page never waits on somebody else's
web server. Facts worth knowing:

- Only the first usable link in the body gets a card. Direct file links (`.zip`, `.7z`,
  `.mid`, `.png`, ...), links back to this site, `localhost`/private addresses and anything
  that is not a public `http(s)` URL are skipped (`extract_post_link()`).
- The fetch is capped at 8 seconds and at the first `LINK_PREVIEW_MAX_CHARS` (150 KB) of the
  page; only `text/html` is read, and a response over the size cap is refused before the body
  is read.
- A page with neither a title nor an image gets no card at all - the post's own link text
  stays as it is. A failed lookup is remembered for an hour and a good card for a week, so a
  page that was momentarily down gets its card on the next edit.
- **Admin -> Posts -> Refresh link cards** re-reads the links in every post (up to
  `MAX_LINK_REFRESH_PER_RUN`, 20 per run - the Free plan allows 50 subrequests per
  invocation). This is how posts written before this feature existed get their cards.

**Links in text are clickable.** A URL written in a post, a comment or a bio is turned into a
real hyperlink when the page is rendered, so `Check https://mediafire.com/file/...` is
clickable without anybody typing HTML. `www.something.com` is linked too (the link is
given an `https://` scheme). Two details:

- Everything else in the body is escaped, so a post containing `<b>` or `<script>` shows
  those characters as text. That is `linkify()` in `src/worker.py`, registered as a Jinja
  filter - the escaping happens there, over each piece of the string, before any anchor is
  inserted.
- The feed shows the first 500 characters of a post, and a URL that runs to that cut is left
  as plain text rather than linked: half a URL is a broken link.

## Mobile layout

The page fits a phone without sideways scrolling, and the two things that used to break that
are worth keeping in mind when editing `public/static/style.css`:

- **A grid track of `1fr` cannot shrink below its widest unbreakable content.** The mobile
  layout uses `minmax(0, 1fr)` for the feed column, so one pasted URL does not stretch the
  page to thousands of pixels wide. Use `minmax(0, ...)` whenever a grid column holds
  user-written text.
- **User text needs `overflow-wrap:anywhere`** (set on post bodies, comments, bios and link
  cards), because a URL or a filename has no break opportunity for the browser to use.

The home page tabs wrap onto a second row under 560px, the feed/sidebar collapse into one
column under 850px, and the sticky header is compacted on small screens.

## Followers and profiles

The site is built as a Google+-style network: profiles have a cover, an About block and
follower counts, people follow each other, and the home page has a **Following** stream.

**Following is one-way and one row.** `follows` (`0008_follows.sql`) stores
`(follower_id, followed_id)` with a composite primary key, so the same person cannot be
followed twice - SQLite rejects the duplicate rather than trusting the application to check
first - and both foreign keys cascade, so deleting an account cannot leave rows pointing at
nobody. Two people following each other is simply two rows.

**The button toggles.** `POST /follow/<username>` follows when you are not following and
unfollows when you are, the same way the vote buttons work. Following yourself is refused in
the route (not just hidden in the template), so a hand-made request cannot create a row the
profile pages would then have to render around. A signed-out visitor gets a Follow link to
`/login?next=...` instead of a button.

**Where followers show up.** `/profile/<username>` shows the counts under the name, up to
`FOLLOW_PREVIEW_LIMIT` (6) followers and followings, and an About block; the counts and the
"View all" links lead to `/profile/<username>/followers` and `/profile/<username>/following`
(capped at `FOLLOW_LIST_LIMIT`, 200). Each row in those lists carries the *viewer's* follow
state as a column, so a list of 50 people renders 50 correct buttons without 50 extra
queries; your own row says "This is you".

**The Following stream** is `/?feed=following`: posts by the people you follow *plus your
own*, which is what Google+ put in your stream. It is a tab on the home page for everyone;
signed-out visitors are sent to sign in first. `?feed=following` and `?category=` are
alternatives rather than combinable filters.

**Redirect targets are checked.** `next` values are only honoured when they are
root-relative (`safe_next()`), so a hand-edited form cannot bounce a visitor to another site;
the sign-in form uses the same guard.

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

So a Git-connected deploy has to run the Python toolchain.

**`.github/workflows/deploy-worker.yml` is that deploy.** It runs on every push to `main`
(and on demand from the Actions tab), installs uv and Node, runs `uv sync --group dev` and
`npm ci`, byte-compiles `src/` as a cheap syntax guard, and then runs
`uv run pywrangler deploy`. `pywrangler deploy` runs its own `sync` first, so Flask is
vendored into `python_modules/` in the build - which is the whole reason the plain
`wrangler deploy` that Workers Builds used by default was wrong.

Two repository secrets have to exist once, under **Settings > Secrets and variables >
Actions**: `CLOUDFLARE_API_TOKEN` (the *Edit Cloudflare Workers* token template is enough)
and `CLOUDFLARE_ACCOUNT_ID`. Without them the workflow stops at its own guard step with a
readable message instead of a wrangler error.

Because this workflow now owns production, **disconnect the dashboard integration** so the
failed `Workers Builds: systematic-bm` check stops appearing on commits - *Workers &
Pages > systematics-bm > Settings > Builds > Disconnect*. Nothing else depends on it, and
leaving it connected means every push races two deploys against each other.

The Workers Builds route is still possible if you would rather keep everything in the
dashboard: connect the repo under *Settings > Builds*, set **Root directory** to the folder
holding `wrangler.jsonc` if the project is not at the repo root, remember the dashboard
Worker name must match `name` in `wrangler.jsonc` (`systematics-bm`), and override both
commands - build: `npm install && curl -LsSf https://astral.sh/uv/install.sh | sh && ~/.local/bin/uv run pywrangler sync`,
deploy: `~/.local/bin/uv run pywrangler deploy`. Its build image is Node-based and Python
Workers are not a documented Workers Builds target, so treat that as something to try, not a
supported path.

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
- **Sign-in is browser-scoped unless "Remember me" is ticked.** Flask writes a session
  cookie with no `Expires` by default, so closing the browser signs you out; ticking the box
  at `/login` marks the session permanent and the cookie then lasts
  `REMEMBER_SESSION_DAYS` (30) days. The tick is not remembered across sign-ins -
  `session.clear()` discards it before the new choice is applied - but it stays ticked if
  the password was wrong, so a retry does not silently drop it.
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
- **Link cards cost one outbound request per URL, at save time only**
  (`ensure_link_preview()` and the cache in `link_previews`). Measured on the deployed
  Worker: a post save is ~130-270 ms CPU with or without a card, one post page ~134 ms, and
  the full feed the most expensive route at ~513 ms - all served on the Free plan. The card
  is fetched from whichever page the link points at, so a site that serves no Open Graph
  tags to a plain HTTP client (`SystematicsLinkPreview/1.0`) simply gets no card.
- **Uploads are D1 rows**, not files and not R2 (`0005_uploads_in_d1.sql`): the `uploads`
  table holds the bytes as a BLOB, and `/uploads/<file>` serves them with an immutable
  cache header. D1 caps a row at 2 MB, so images are limited to `MAX_IMAGE_BYTES`
  (1.7 MB) and to png/jpg/jpeg/gif/webp; anything else - or anything larger - is refused
  with a flash message instead of being dropped silently. Browsers cache the images, so a
  page view does not re-read every avatar.
- **Bind image bytes to D1 as plain Python `bytes`.** Not wrapping them in `to_js()` first is
  what makes uploads work at all. A converted value reaches the Workers RPC layer as a typed
  array, and `rpc.python_to_rpc()` walks it element by element to prove it can be sent -
  measured at roughly 3.5 us per byte, i.e. **~2.2 s of CPU for a 600 KB image**. That blew
  the runtime's CPU budget, and because the failure happens inside the runtime rather than in
  Flask it surfaced as Cloudflare's bare `error code: 1101` (or 1102) page instead of a
  flash: every image above roughly 100 KB failed, and 100 KB itself failed about half the
  time. Raw bytes are not walked, and D1 stores them as a BLOB just the same - the insert
  dropped from 2.2 s to **86 ms** for the same 600 KB. Never hand a converted
  `to_js(...)` blob to `stmt.bind()`.
- **An uncaught runtime error still answers with a page.** `UnhandledErrorPage` wraps the
  WSGI app: the runtime's `CpuLimitExceeded` derives from `BaseException`, so it never
  reaches Flask's error handling, and the visitor used to get Cloudflare's `1101` page. The
  wrapper logs the traceback (readable in `wrangler tail`) and returns a small 500 page.
  Anything Flask does catch is unaffected.
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
| Sign-up with no image | ~86 ms |
| Sign-up with a 10 KB / 100 KB image | ~83 ms / ~103 ms |
| Sign-up with a 400 KB / 1.6 MB image | ~181 ms / ~1.46 s |

Measured on the deployed Worker instead (CPU time from `wrangler tail`), which is the
number that actually matters:

| Deployed behaviour | Result |
| --- | --- |
| Page renders, static assets, `/uploads/*` | 6-32 ms CPU, all served (the runtime allows occasional overshoot) |
| Sign-in (100,000-iteration PBKDF2) | served, no CPU error |
| Sign-up with a 100 KB / 300 KB / 600 KB image | served: 269 / 117 / 149 ms CPU |
| Sign-up with a 1.2 MB image | served: 664 ms CPU |
| Sign-up with an image above the cap (1.75 MB, 5 MB) | friendly flash, not an error page |
| Image served back from D1 (`/uploads/*`) | 200, byte-identical, including at 1.3 MB |

So nothing here is refused outright on the free plan any more: images up to
`MAX_IMAGE_BYTES` are accepted, stored and served, and the runtime simply runs well past the
10 ms budget while doing it. Keep avatars and banners reasonably small anyway - a 1.6 MB
upload costs over a second of CPU, and that budget is not unlimited.

Two consequences:

- Password hashing is no longer the problem: native WebCrypto brought a sign-in down to
  roughly the cost of rendering a page (it used to be ~0.35 s and dominate everything).
- **Image uploads are still the expensive part**, because the bytes are read and stored in
  Python. What the `to_js` fix removed was an accidental per-byte RPC cost, not the cost of
  the data itself, so a 1.6 MB upload still costs over a second of CPU. A request body above
  `MAX_CONTENT_LENGTH` (4 MB) is refused with a flash before Flask ever parses it.
  On Workers Paid the 30 s CPU default handles all of this comfortably.

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

Systematic wrote this
