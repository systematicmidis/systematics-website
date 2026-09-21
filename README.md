# Systematics Black MIDI site

A small Flask community site (accounts with bios, avatars, custom profile banners and social
links, followers, posts, two feeds, likes/dislikes and threaded comments) that runs on **Cloudflare Workers**
using the Python Workers runtime and D1 - and that fits on the **Workers Free plan, with no
payment method on file**. See ["Running free"](#running-free-no-payment-method) for what that
costs and limits.

| Piece | Cloudflare product | Where it lives |
| --- | --- | --- |
| Flask app (routes + Jinja templates) | Python Workers (`workers-py` / `pywrangler`) | `src/worker.py`, `src/templates/` |
| Users (with bios), posts, comments, votes, follows | D1 (SQLite) binding `DB` | `migrations/` |
| Conversations, their messages, and the moderation log | D1 tables `conversations`, `messages`, `moderation_log` | `migrations/0014_messages.sql`, `0015_direct_messages.sql` |
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

- **Node.js 22+** and npm - `pywrangler` shells out to `npx wrangler`, and wrangler
  refuses to start on Node 20 (`Wrangler requires at least Node.js v22.0.0`).
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

## Settings page

`/settings` - reached from **⚙ Settings** in the nav, in the sidebar, or on a phone from the
same nav - has three sections, and each is shown to a different audience.

**Appearance** is for everybody, including signed-out visitors: a **Light / Dark** switch. The
choice is stored in the browser (`localStorage`, key `smm-theme`), never in the database, so it
works without an account and needs no round trip. `<html data-theme="light|dark">` is set by a
tiny inline script in `src/templates/base.html` *before* anything is painted, which is what
stops a dark-mode visitor seeing a white flash on every navigation, and
`public/static/theme.js` handles the clicks and keeps every control in step. Until somebody
picks a theme explicitly the site follows the operating system's own preference and keeps
following it live. All the colours live in the `html[data-theme="dark"]` block at the foot of
`public/static/style.css`; the rest of that file is untouched, so light mode cannot regress.
The ☾ / ☀ button in the top bar is the same switch in one click.

**Account** is a signpost for signed-in people (display name, user ID, member since, links to
profile settings, your profile, your followers, sign out) and a "create an account" prompt for
everyone else.

**Site owner** appears *only* for the accounts in `OWNER_USERNAMES`. It shows totals for the
whole site (accounts, published posts, drafts, comments, votes, follows, images stored and
their total size, link cards), the configuration actually in effect (owner accounts, whether
`ADMIN_PASSWORD` is set, the PBKDF2 work factor, max image size, session lifetime, link-card
TTL), the draft posts nobody else can open, the newest accounts, and two owner actions: write
a Systematics post, or rebuild every link card. The panel is rendered conditionally *and* the
only action behind it, `POST /settings/refresh-links`, is gated by `@owner_required` - hiding
markup is not access control. To add a second owner, add the username to `OWNER_USERNAMES` in
`wrangler.jsonc` (or the dashboard) and redeploy; no code change is involved.

## Deleting your account

The Account card on `/settings` ends with **Delete my account**, which only *links* to
`/settings/delete-account` - following a link never destroys anything. The confirmation page asks
for two separate deliberate acts before it does anything: typing your username exactly, and
ticking "I understand that my account cannot be recovered". Owner accounts get an extra warning
there, because owner rights come from `OWNER_USERNAMES` rather than from the account, so deleting
the account frees the name for anyone to register - and whoever registers it becomes an owner.

Deleting is a **soft delete**, and it is the reason the `users` row survives: a hard `DELETE`
would cascade through `posts` and `comments` and take everything the person ever wrote with it,
leaving one-sided threads behind. What goes instead is everything that identifies them:

| Kept | Removed |
| --- | --- |
| the row, their posts, their comments, their votes, the moderation log, every conversation they were in | display name (becomes `[ Account Deleted ]`), username (released, freed for reuse), password hash, bio, avatar, banner, every `follows` row in either direction |

Their profile then 404s like an unknown account, their comments and posts render as
`[ Account Deleted ]` with a ✕ avatar and no profile link, and the account can never sign in
again. The admin panel lists them as `deleted` with nothing left to restrict.

## Bans

Moderation lives in the admin panel (`/admin`, section *Accounts*), where every account row has a
**Ban** box, a **For** box, a **Because of** box and an optional reason. The six bans are:

| Ban | What it stops |
| --- | --- |
| Temporary comment ban | commenting (for the chosen span) |
| Comment ban | commenting, permanently |
| Temporary post ban | writing or editing posts |
| Post ban | writing or editing posts, permanently |
| Temporary account ban | signing in at all |
| Permanent account ban | signing in at all, with no expiry |

The *For* box (1 hour / 1 day / 3 days / 1 week / 30 days) applies to the two temporary bans and
is ignored by the permanent ones. Enforcement is server-side and in three places: an account ban
is checked in `before_request` and again at sign-in (clearing the session, so a banned browser
stops being accepted at all), a comment ban is checked before a comment is inserted, and a post
ban before a post is created or edited. A banned person still *reads* what they were banned from
writing, and the site shows them a moderation notice on every page explaining what is restricted
and until when.

Temporary bans are stored as an expiry and evaluated on read, so they lift themselves the moment
they run out - nothing sweeps them, and the admin panel simply stops listing them. Owner accounts
and your own account cannot be banned: owner rights would survive a ban, so it would only lock the
owner out of their own panel. Lifting is a per-account **Lift bans** button (or `kind=account`,
`comment` or `post` to clear just one).

**Because of** is what makes a ban explain itself later. It is a list of that
account's own newest posts and comments (built by `moderatable_content()`, two queries for the
whole page rather than one per account); picking one attaches it to the ban, and the panel then
shows it on the account row as *"Because of their comment on …"* and keeps it in the **Moderation
history** at the foot of the page. The reason and the attached post or comment are also sent to
the banned person - see **Messages** below.

Bans are migration `0009_account_deletion_and_bans.sql`, which adds columns to `users`, and the
inbox they write into is migration `0014_messages.sql` (and the conversations it is made of,
`0015_direct_messages.sql`) - so run `npm run db:remote` **before** the
deploy that carries this code, since the GitHub Action ships code and never migrations.

## Messages

Messaging is a Hangouts-shaped screen rather than a page of links. `/messages` is two panes: the
people you have spoken to down the left - one row per conversation, newest first, with whoever
spoke last and what they said - and the conversation itself on the right of them. Choosing a row
opens that thread beside it, and `/messages/c/<id>` is that same screen with the thread already
chosen, so a shared link and a click in the list are one view. In the thread your own lines are
tinted and pushed right, theirs flat on the left, and `Seen` marks a message the other person has
opened. The rail carries the unread count, an unread row is tinted and badged **N new**, and the
open thread is ruled on its left. **Mark all read** clears the lot.

The left column is the same on all three screens - the inbox, an open thread and the first message
to somebody new - so moving between conversations never loses your place, and the whole thing comes
from one template (`messages.html`, whose right-hand pane `conversation.html` fills in) rather than
three that drift apart. The inbox opens on an empty pane instead of jumping into the newest
conversation, because opening a thread is what marks it read: a moderation notice must not be
marked read by a page nobody chose to open. A conversation starts from the **Message** button on
anybody's profile (beside Follow) or from the box at the top of the list, which takes a handle.
Nothing is written until the first line is actually sent, so following a link cannot litter the
database with empty threads.

A thread belongs to exactly two accounts: `conversations` stores the pair as
`user_low`/`user_high` (always smaller id first, `UNIQUE(user_low, user_high)`), so the same two
people cannot end up with two conversations. Every message is a row in `messages` - the table
migration 0014 introduced - carrying the `conversation_id` it belongs to, `sender_id`,
`recipient_id` and `read_at`. Unread is therefore just *messages addressed to me with no read
mark*, per thread or in total, and `last_message_at` is stamped on every send because the inbox
orders by it. Anyone can message anyone signed in; a third account opening somebody else's thread
gets a **404**, and posting into it is refused (`@app.route` checks the reader's own id, never an
id from the address bar).

### The moderation account

The site writes as a real account, not as a disembodied bot label: **`SystematicsModeration`**
(`MODERATION_USERNAME_DEFAULT`, overridable with the `MODERATION_USERNAME` Worker variable). Ban
notices, lifted-ban notices and anything an admin types in the panel are messages *from that
account*, so they land in an ordinary conversation that the person can simply reply to - and the
reply arrives in the same thread, which the admin panel reads and answers.

That is what `moderation_account()` (one lookup per request, cached on `g`) and
`conversation_with_moderation()` are for: an admin may read and write the site's side of a thread
because that account has no session of its own.

The list down the left of such a thread comes from `inbox_threads()`, which hands an admin standing
in the site's conversations and everybody else their own: the pane can never show a thread the
column beside it denies exists, and the shared `ADMIN_PASSWORD` - not an account, so it has no
inbox of its own - still gets the site's list rather than an empty column. The panel's **Site
messages** section lists those conversations with their unread reply counts, opening one marks the
site's side read, and the **Message &lt;name&gt; as the site** box on any account row writes into
the same conversation. A thread the admin is standing in shows a note saying whose voice the box
below is; the bubbles still line up on the site's side, because that is who is speaking.

**If the account is missing, nothing breaks.** A fresh local database (or a renamed account) has
no voice to write as, so `notice_conversation()` returns nothing, notices are written with
`conversation_id` NULL, and the inbox lists them under **Notices** instead of dropping them.
`/messages/<id>` still renders one on its own page, and a ban still applies - it is only the
threading that is missing. Migration `0015_direct_messages.sql` backfills any notice written before
the account existed into the thread it would have used, guarded on the account being present.

### What a notice says

`send_ban_notice()` and `send_unban_notice()` compose notices from the ban itself: what was decided,
how long it lasts, what is still open to the person (phrased from `BAN_SCOPE_NOTES`, beside
`BAN_MESSAGES` so the banner and the message cannot disagree), the reason the admin typed, and the
post or comment the ban was attached to - quoted in full and linked, so the notice still explains
itself after that comment has been deleted. The acting admin is named inside the body
(`Applied by: <handle>`) because the site speaking and a person speaking should not look like the
same thing, and the notice ends by inviting a reply, which is now something the person can actually
do. A temporary ban that simply runs out sends nothing: nobody lifted it, so there is nothing to
announce.

The notice records the ban it is about (`ban_kind`, `ban_permanent`, `ban_until`), but whether that
ban is *still* in force is asked of the account at read time, so a notice never keeps claiming
somebody is banned after the ban was lifted or ran out - in a thread it says *"no longer in force"*,
and the single-notice page says the same. That is also why the row is a **snapshot**: the excerpt,
its post's title and its URL are copied in when the notice is written, so nothing is looked up when
it is rendered, no message can be used to reach a post the reader was not allowed to see, and the
text cannot change under the person who received it. Bodies go through the same `linkify` filter as
every other body of text on the site, so a link is clickable and markup is text.

**An account ban is the one case the inbox cannot serve.** Reading messages needs a session, and an
account ban is exactly what clears it - so that notice is shown on the sign-in page instead, from
`notice_for`, the account id left in the freshly cleared (still signed) session by
`enforce_moderation()`.

### Admins, and the record

Every ban, lifted ban and hand-written message is also written to `moderation_log` (who, what, why,
which content, and a link to the offending post or comment), which is what the panel's **Moderation
history** lists newest first. It exists because the columns migration 0009 added to `users` only
remember the *last* ban; the log remembers all of them, and `latest_ban_causes()` reads the newest
ban per account out of it, so *"what did they get banned for?"* still has an answer months later.

**Deleting an account leaves its conversations standing.** A thread belongs to both people in it,
so closing one account must not quietly delete what its owner was told, nor erase the other
person's half of a chat: the thread stays, reading as `[ Account Deleted ]` with a ✕ avatar, and the
other person can still read it and write into it. The tombstone cannot sign in, so nothing in it is
readable to whoever left. The moderation log stays for the same reason, and it stores no message
bodies.

A message is capped at `MAX_DM_LENGTH` (2,000 characters, the same ceiling as a comment) and the
timestamp on your own line reads `Sent` until the other person opens the thread, then `Seen`. Every
read of the new tables is wrapped so a database without `0015_direct_messages.sql` degrades instead
of failing: the inbox renders with an empty conversation list, an existing thread 404s, starting one
answers *"Messages are not available right now"*, and the admin panel shows the section with a note
saying which account to create.

## Posting, feeds, votes and replies

**Anyone with an account can post.** Signed-in users see "Write" in the nav and a
"Write a post" button on the feed; posts appear immediately (no moderation queue), and the
author can edit or delete their own post from the post page. Site owners can additionally
edit or delete *any* post, keep a post as a draft, and file it into either feed.

**A post lives at `/<account number>/posts/<post id>`** - the account of whoever wrote it,
then an 11-character post id in the shape Google+ used, from `secrets` in
`generate_post_public_id()`:

```
/1/posts/WU4Qec9X6os
```

A post id is unique on its own, so the leading number does not identify anything: the post is
looked up by its own id and a read carrying the wrong number (an account id from before a
migration, somebody else's, or none at all) is **301'd to the right address** instead of being
served a second time. Ids are random rather than sequential, so a post's age and its neighbours
cannot be read off its URL.

Two other spellings are still accepted rather than 404ing, and both redirect to the canonical
address on a read (`post()` and `post_legacy()` in `src/worker.py`):

| Requested | What happens |
| --- | --- |
| `/posts/<post id>` | 301 to `/<account number>/posts/<post id>` - the shape handed out between migrations `0012` and `0013`. A post with no author at all (the seeded welcome post) lives here instead, because it has no number to lead with. |
| `/post/<row id>` | 301 to the canonical address - the original numeric-row-id shape. |

A **write** is never redirected away from on any of the three: the comment is saved first and
the redirect follows, so a comment typed into a page opened before this change is not lost.

Templates never spell the shape out. `url_for("post_with_author", ...)` is not used; they call
the `post_url(post)` global with the post row, so the address exists in exactly one place
(`canonical_post_path()`). That works because every query that feeds a template selects
`users.user_id AS author_public_id` - a row without it falls back to `/posts/<post id>`.

Accounts carry their own public id: the `users.user_id` shown as **User ID** on the profile and
settings pages, and the first segment of every post URL its owner writes. It is the account's
**place in the signup order** - the first account on the site is `1`, the next `2`, and so on
(`0013_sequential_profile_ids.sql`). Numbers are taken one past the highest in use
(`next_profile_id()`), so one is never handed to two accounts and never reused after a member
leaves - which is what keeps a URL stable. Registration retries on the UNIQUE constraint, so two
signups in the same instant cannot collide. Migration `0012` had reissued these ids as random
21-digit numbers (the shape `plus.google.com` used); the original 16-character hex token is still
kept in `users.legacy_user_id`.

**Two feeds.** Every post carries a category, and `/?category=community` or
`/?category=systematics` filters the feed (the tabs on the home page). Regular accounts can
only write to **Community posts** - the category is decided from the author's account, so a
forged `category` form field is ignored (`post_category_for()` in `src/worker.py`). Only
accounts listed in `OWNER_USERNAMES` land in **Systematics posts**, which stays your channel
while the community has its own. Draft posts are unlisted: only their author and site owners
can open a draft at its own URL for them.

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

**Link text can replace the address.** Writing `[the words](https://example.com)` makes "the
words" the link and hides the address, which is how a pasted download URL stops dominating a
sentence. Only the address goes in the brackets - the visible text is escaped like any other
user text, so a label containing `<b>` shows those characters rather than markup, and the
address is used only as the `href`. The form has to start with a scheme or `www.`, which is
what stops a hand-written `[click](javascript:...)` from becoming an anchor. Nothing else of
Markdown is implemented. In a feed excerpt that cuts through a bracket link, the label
survives and the address is dropped, since half an address is not a link.

It is the same `linkify()` filter everywhere, so a comment or a bio can use both spellings
too.

**The update-log placeholder fills itself in.** Google+ never resolved one of its own
strings - notification mails went out reading `[DATE] at [LOCAL USER TIME ZONE]`. A post may
write that phrase, or just `[DATE]`, and `linkify()` replaces it with the post's own date and
time: `2026-09-19 9:07 pm`. The phrase is matched as a unit, so the "at" between the two
tokens is not left stranded on its own. A bare `[LOCAL USER TIME ZONE]` still matches and
renders as nothing, which is what keeps a post written while it printed the zone from showing
raw brackets. Matching is case-insensitive, and a post with no usable timestamp leaves the
tokens alone.

The clock is 12-hour rather than the site's 24-hour one, because this is a line of prose
inside a post. The instant is UTC on the server and `public/static/localtime.js` restates it
on the reader's own clock, because only the browser knows which zone the reader is in: the
stamp carries the UTC instant in `data-log-time` and the deferred script rewrites the text.
**No zone name is printed** - the stamp is unambiguous to the person already reading it.
Without JavaScript the line still reads correctly, just as UTC, which is how every other date
on the site is shown, and the `<time datetime>` attribute stays the true UTC instant either
way.

Substitution runs on the plain runs of text inside `linkify()`, never on a URL, so a link
like `https://example.com/[DATE]/x` keeps its own address intact.

**The update log can read the repository.** A post that writes `[COMMITS]` gets the newest
commits from `systematicmidis/systematics-website`, one line each: the commit's own time on the
reader's clock, then the commit subject. Nothing in the list is a link - it reads as a list of
changes rather than a list of links, and a commit subject is still escaped like any other user
text. That is what keeps an update log current without being edited: pushing a commit adds a
line.

The public GitHub API needs no token, so the Worker holds none; the list is read anonymously,
cached in `commit_log` (migration `0011`) and re-read at most once per `COMMIT_LOG_TTL_SECONDS`
(5 minutes), because the unauthenticated API allows 60 requests an hour per IP address and a
Worker's egress addresses are shared with every other Worker. Facts worth knowing:

- The refresh happens when a post containing `[COMMITS]` is rendered, so the log is current
  within the interval rather than instantly. **Settings -> Refresh the commit log** (owner only)
  re-reads it on the spot. Set the Worker variable `COMMIT_LOG_REPO` to point at another
  repository.
- The attempt is recorded *before* the request goes out, and a failed one is not retried for
  `COMMIT_LOG_RETRY_SECONDS` (15 minutes). So a rate-limited or unreachable GitHub is asked once,
  and the cached list is kept and still rendered - a post never shows an error in place of the
  list, and never replaces a good list with nothing.
- A feed card shows only the newest commit (`COMMIT_LOG_EXCERPT_LIMIT`); the whole list belongs on
  the post.
- Only the subject line of a commit message is stored, truncated to `COMMIT_LOG_MESSAGE_LIMIT`
  characters, and every line is escaped - a commit message is somebody else's text. No address
  is stored at all: the cached row holds the commit id, and `COMMIT_SHA_RE` holds both GitHub's
  response and the cached row to that shape, so a row written into the cache by anything else
  is dropped instead of printed.

## Mobile layout

The page fits a phone without sideways scrolling, and the two things that used to break that
are worth keeping in mind when editing `public/static/style.css`:

- **A grid track of `1fr` cannot shrink below its widest unbreakable content.** The mobile
  layout uses `minmax(0, 1fr)` for the feed column, so one pasted URL does not stretch the
  page to thousands of pixels wide. Use `minmax(0, ...)` whenever a grid column holds
  user-written text.
- **User text needs `overflow-wrap:anywhere`** (set on post bodies, comments, bios and link
  cards), because a URL or a filename has no break opportunity for the browser to use.

The home page tabs wrap onto a second row under 560px, and under 850px the rail leaves the side
of the window for the top: the brand and the theme/sign-out buttons on one row, then every link
as one strip that scrolls sideways. That strip is usually wider than the phone - it has its own
scrollbar - so the page itself still measures exactly the width of the viewport.

The messages screen is two panes on a desktop and one at a time on a phone: under 850px the list
is what you get while nothing is open, and once something is, the conversation takes the screen and
the header's **← All messages** link is the way back (the `has-pane` class on `.dm-shell` is what
switches between them). Type is what shrinks first: the rail, the list rows and the bubbles all
step down at 560px rather than forcing a sideways scroll.

## Shape of the page

The shell copies Google+: every link lives in a rail against the left edge of the window, the
stream is one narrow column centred in the space that is left over, and there is no top bar.
`base.html` renders `.app` (a two-column grid), `.rail` and `.stream-col`. `is-active` is worked
out per link from `request.path` and the query string rather than hard-coded, so the rail says
where you actually are - which matters for the two category feeds and the following stream, whose
URLs differ only in their query.

The rail is `position:sticky` and as tall as the window, so it holds still while the stream
scrolls past it, and `margin-top:auto` keeps its note and the theme/sign-out buttons at the foot
of the window on a short page. Under 850px it becomes the two-row strip described in **Mobile
layout**. Because the rail is inside `body { overflow-x:hidden }`, every new rule that scrolls
sideways has to do it on an element inside the rail rather than on the page.

**Page changes fade and rise.** Each child of `.feed` runs one `stream-in` animation on load
(opacity 0 to 1, 8px up, 300ms on `cubic-bezier(0,0,0.2,1)`), with the first four items staggered
36ms apart, so a navigation reads as the stream swapping in place instead of the window blinking.
Both numbers are Google+'s: its CSS ran its transitions in a 100-400ms band on two easings, and
the one doing almost all the work was this decelerate curve. It is a CSS animation, not
JavaScript, so nothing has to run for a page to be readable, and
`@media (prefers-reduced-motion: reduce)` switches it off for anyone who asked for that.

## Design tokens (read out of Google+ 2016's own CSS)

The colours, type scale and spacings in `public/static/style.css` are not eyeballed from a
screenshot. Google+ inlined its whole stylesheet into each page - 116KB of it, with obfuscated
class names like `.XVzU0b` and quantumWiz animation names - so the archived pages carry the real
declared values. Read one back with the `id_` modifier, which returns the original rather than
Wayback's rewritten copy:

```bash
curl -sS --max-time 120 -A 'Mozilla/5.0' \
  'https://web.archive.org/web/20161123160000id_/https://plus.google.com/+Google/posts' \
  -o /tmp/gplus.html
```

What the stylesheet declares, and what this site therefore uses:

| Token | Value | Where it came from |
| --- | --- | --- |
| Font stack | `Roboto, RobotoDraft, Helvetica, Arial, sans-serif` | its `font-family`, including the `RobotoDraft` alias |
| Base type | `14px / 20px` | the most frequent pairing in its file (then 14px/18px for tighter rows) |
| Emphasised type | weight **500** | 44 uses of 500 against 12 of 400 - nothing in the scale is 700 |
| Smallest type | **12px** | its scale runs 12, 13, 14, 16, 18, 20, 24, 34 - there is no 10px or 11px in it |
| Primary ink | `rgba(0,0,0,0.87)` (`#212121`) | its most-used text colour, also what a stream post renders in |
| Secondary ink | `rgba(0,0,0,0.54)` | icon fills and 16px/500 labels |
| Tertiary ink | `#9e9e9e` | timestamps and metadata captions |
| Divider | `#e0e0e0` | `border-top:1px solid #e0e0e0` on its cards |
| Link / primary blue | `#4285f4` | 30 uses, e.g. `.HQ8yf a { color:#4285f4 }` |
| Google red | `#db4437` | accents and destructive states |
| Card | `#fff`, `border-radius:2px`, **no shadow** | 2px is its workhorse radius; elevation (`0 8px 10px 1px rgba(0,0,0,.14)` + two layers) was for menus and dialogs, not a card in a stream |
| Hover fills | `#f5f5f5`, `#fafafa` | `.cjGgHb .Vmcec:hover { background-color:#fafafa }` |
| Spacing | 8px grid: `0 16px`, `16px`, `0 24px`, `8px` | its most frequent paddings |

Three rules follow from the table and are easy to undo by accident:

- **`--shadow` is not for cards.** The tokens declare it so the phone rail strip (the one surface
  that floats over scrolling content) has one, but a card in the stream is a hairline and nothing
  else. Adding a shadow back to `.post-card` is a visible departure from the reference.
- **Nothing typed by a person drops below 12px**, because nothing in Google+'s scale did. A new
  metadata line at 11px is off-scale rather than merely small.
- **`b` and `strong` are 500 globally**, so a heading written with `<strong>` lands in the
  declared weight instead of the browser's 700.

Roboto is fetched from Google's font CDN in `base.html` (windows and iOS do not ship it), and only
the two weights the scale declares - 400 and 500. The stack keeps Helvetica and Arial behind it,
so the page is unchanged if that request fails.

Two things the reference does not settle, recorded so nobody re-derives them: the measured page
field in the archived screenshot is `#f1f1f1`, but no `#f1f1f1` appears in the CSS - its surfaces
are `#eeeeee`/`#f5f5f5`/`#fafafa` - so `--bg` keeps the `#f1f3f4` it already had. And transitions
cannot be read out of a still image or an 11-second clip of a static page, which is why the only
motion values here are the ones the CSS declares.

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

**Social links are a profile's other addresses.** *Edit profile* has a box per platform
(YouTube, X (Twitter), TikTok, Instagram, Discord, Twitch, SoundCloud, Bandcamp, GitHub and a
Website) plus three free rows for anything else, where the name is optional and falls back to
the link's own domain. They are stored as one JSON array in `users.social_links` rather than a
column per network (`0010_social_links.sql`), because the sites people use keep changing and an
"other" link has no fixed name to give a column. The profile header renders them as a chip
strip under the bio, and the About block lists them with their addresses - "YouTube" alone does
not say *which* channel.

**Links are validated in both directions.** `normalise_social_url()` accepts a bare
`youtube.com/@you` (nobody types the scheme into a "your channel" box) and adds `https://`, then
requires an http(s) address on a public domain - the same `is_public_url()` guard the link-card
fetcher uses, so `javascript:` or `http://192.168.1.1/` cannot reach a profile. `social_links_of()`
re-runs that check when reading the column back, so a row edited by hand in D1 can make a link
disappear but never smuggle one in. One bad link refuses the whole save and names the box it
came from instead of silently dropping it, a profile is capped at `MAX_SOCIAL_LINKS` (13), and
closing your account clears the column along with the bio and the images.

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

- **A session cookie is checked against the database, not just for its presence.** `login_required`
  reads the account row (`current_user()`) and, when the row is gone - a database restored from a
  backup, a local one reset, an account removed by hand in D1 - clears the cookie and sends the
  visitor to sign in with an explanation. The comment and vote routes resolve the account the same
  way instead of trusting `session["user_db_id"]`, because they insert rows keyed to that id. This
  is not hypothetical: a cookie naming a missing row reached `/messages` and raised a
  `TypeError` through the view, which in front of a Cloudflare Worker is an error 1101 for whoever
  is reading.
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
- **Posts are addressed by id**: `/<account number>/posts/<post id>`, not `/post/some-slug`. The
  `slug` column was dropped in `0003_posts_use_ids.sql`, so old slug URLs now 404; `/posts/<post id>`
  and `/post/<row id>` redirect to the canonical shape, and a wrong account number in front of a
  post id is corrected with a 301 rather than 404ing. The post editor no longer asks for a slug.
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
| Page render (`/`, `/<account number>/posts/<post id>`) | ~15-25 ms |
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
