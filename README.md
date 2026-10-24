# TrustVault

Secure document sharing with a real audit trail, built for the Snovasys Fresher Hiring Challenge 2026.

- **Live site:** https://trustvault-demo-li4x.onrender.com (the free host sleeps when idle, so the first request can take about a minute)
- **Demo video:** https://drive.google.com/file/d/17J7K8mvOWADAKkbHo-vHb5E90yfx0M7h/view?usp=sharing
- **Write-up:** [WRITEUP.md](WRITEUP.md)
- **Threat model:** [THREATS.md](THREATS.md)
- **How I used AI:** [PROMPTS.md](PROMPTS.md) and [CLAUDE.md](CLAUDE.md)

## Demo accounts

| Role | Email | Password |
|---|---|---|
| Admin | `admin@trustvault.test` | `AdminDemo#2026` |
| Owner | `owner@trustvault.test` | `OwnerDemo#2026` |
| Viewer | `viewer@trustvault.test` | `ViewerDemo#2026` |

On the login page, the three role buttons fill these in for you. These credentials are public on purpose, as the challenge requires. The demo admin can approve accounts, change roles, lock users and export activity, but it can **not** read file contents.

The live site has four sample documents. The owner has all four, and the viewer has three. The board minutes are private to the owner, and the contract can be edited by the viewer.

## Try it in two minutes

1. Log in as the **owner**. Upload a PDF, open it, and share it with the viewer. The sharing panel is a searchable checklist, so you can tick several people at once.
2. Log in as the **viewer**. The document is there and can be downloaded. Try to reach the owner's private "Board minutes" document and you cannot: it is not listed and its address answers "not found".
3. Back as the owner, click **Revoke**. The viewer's very next request fails.
4. Log in as the **admin**. Open Activity to see every action and every refusal, click **Verify now** to re-check the tamper-evident log, and open Users to approve or lock accounts.

## What it does

- **Three roles, plus a waiting state.** New accounts start as `pending`: they can log in but can do nothing, appear in nobody's sharing list and can not be shared with until an administrator gives them a role.
- **One decision point.** `server/src/authorize.js` decides whether someone may read, download, edit, delete or share a document. It denies by default, reads the database on every call, and is reached through `server/src/guard.js`, which answers 404 and records the refusal.
- **Per-document permissions** for named people at `read` or `edit` level, with optional expiry. Owners grant and revoke. Revoking works on the very next request, because nothing is cached and no tokens or links carry permissions.
- **Editing.** A person with edit access can change a document's title and category and replace its file. The previous file is kept as an earlier version that only the owner can see and download.
- **Upload checks.** The real file type is read from the file's first bytes and must be PDF, PNG, JPG, DOCX or XLSX. The limit is 10 MB. Files are stored in the database as bytes, so no filename ever becomes a path.
- **Search** by name, owner, category and date. The permission rule is inside the SQL, so documents the caller may not see are never fetched or counted.
- **Audit trail.** Uploads, downloads, edits, deletions, permission changes, logins and **refusals** are all recorded. The database refuses to change or delete log rows, each row holds a hash of the previous one, and the admin can re-verify the whole chain at any time.
- **Admin view.** Overview (counts and things worth noticing), Activity (filterable, with CSV export), Users (approve, change role, lock, with CSV export).
- **Passwords.** Hashed with argon2, with rules enforced on the server (at least 6 characters with an uppercase letter, a lowercase letter, a number and a special character). Forgotten passwords are reset by the person with one of eight one-time recovery codes they saved earlier. No administrator can reset anyone's password.

## Permission model

| Role | What they can do |
|---|---|
| `admin` | Run the system: approve and lock accounts, change roles, read the activity log, verify the chain, export. **No access to file contents** unless they were never involved: they get "not found" like any stranger. |
| `owner` | Upload documents, share them, change who has access, delete their own documents, see version history. |
| `viewer` | Open only the documents shared with them. |
| `pending` | Nothing, until an administrator gives the account a role. |

| Grant level | Can do |
|---|---|
| `read` | See the document and download it |
| `edit` | Everything in `read`, plus change the title and category and replace the file |
| the owner | Everything above, plus delete, share and see version history |

A role says what kind of person you are. A grant says which document you were given. A role alone never opens a document.

## API: who may call what

Refused requests for a document answer **404** (the same as "does not exist") and are audited. Refused requests for a role-restricted endpoint answer **403** and are audited. A missing login answers **401**. "Document owner" means the person who uploaded that document.

### Pages and health

| Endpoint | Who |
|---|---|
| `GET /` and the files in `server/public` | Anyone |
| `GET /health` | Anyone |

### Accounts (`/api/auth`)

| Endpoint | Who |
|---|---|
| `POST /register` | Anyone (rate limited). Same reply whether or not the email exists |
| `POST /login` | Anyone (rate limited) |
| `POST /reset-with-code` | Anyone holding the email and a valid unused recovery code (rate limited) |
| `POST /logout`, `GET /me` | Logged in |
| `POST /change-password` | Logged in, needs the current password |
| `GET /recovery-codes` | Logged in (how many codes are left) |
| `POST /recovery-codes` | Logged in, needs the current password |

### Documents (`/api/documents`)

| Endpoint | Who |
|---|---|
| `GET /` (list and search: `q`, `owner`, `category`, `from`, `to`, `limit`, `offset`) | Logged in. Returns only documents the caller owns or holds a current grant for |
| `POST /` (multipart: `file`, `title`, `category`) | Role `owner` |
| `GET /:id`, `GET /:id/download` | Document owner, or anyone with a current `read` or `edit` grant |
| `PATCH /:id` (`title`, `category`), `POST /:id/replace` (multipart `file`) | Document owner, or anyone with a current `edit` grant |
| `DELETE /:id` | Document owner |
| `GET /:id/versions`, `GET /:id/versions/:version/download` | Document owner |

### Sharing (`/api/documents/:id/grants` and `/api/directory`)

| Endpoint | Who |
|---|---|
| `GET /api/documents/:id/grants` | Document owner |
| `POST /api/documents/:id/grants` (`email`, `level` of `read` or `edit`, optional `expires_at`) | Document owner. The target must be an active, approved viewer or owner |
| `DELETE /api/documents/:id/grants/:grantId` | Document owner |
| `GET /api/directory` | Role `owner`. Lists approved viewers and owners |

### Administration (`/api/admin`)

All of these need the role `admin`.

| Endpoint | What |
|---|---|
| `GET /audit` | The activity log (filters: `group`, `action`, `outcome`, `actor`, `document_id`, `from`, `to`, `limit`, `offset`) |
| `GET /audit/export` | The same filters as a CSV file. The export is itself recorded in the log |
| `GET /audit/verify` | Re-computes the whole audit chain |
| `GET /summary` | Counts for the last 24 hours and accounts worth a look |
| `GET /users`, `GET /users/export` | The user list, and as CSV. Never includes password data |
| `PATCH /users/:id` (`role` and/or `is_active`) | Approve, change role, lock or unlock. An admin can not change their own account |

## Run it yourself (from a clean clone)

You need **Node.js 22** and a **PostgreSQL** database. A free [Neon](https://neon.tech) project works well. Use one database for running the app and a **separate one for the tests**.

```bash
git clone https://github.com/23jr1a05d9/trustvault.git
cd trustvault/server
npm install
```

Create `server/.env` (see `server/.env.example`):

```
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require
PORT=3000
```

Then create the tables and the demo data, and start the app:

```bash
npm run migrate       # creates the tables, triggers and rules (safe to run again)
npm run seed          # the three demo accounts
npm run seed-demo     # four sample documents and shares
npm run dev           # http://localhost:3000
```

Do not set `NODE_ENV=production` on your own computer: the login cookie is then marked `Secure` and will not stick over plain `http`.

| Command | What it does |
|---|---|
| `npm test` | Runs every suite in `server/tests` against the database in `.env` |
| `npm run audit-check` | Verifies the audit chain and shows that editing a log row is refused |
| `npm run create-admin` | Creates the first administrator (see below) |

### Tests

`npm test` creates its own users and documents and removes them afterwards. The audit rows stay, because the log can not be changed. **Run the tests against a development database, never against production.** The tests cover each of the cases in `THREATS.md`: strangers, other owners, admins, revoked and expired grants, upload abuse, search leaks, injection text, the audit chain, password reset and export.

### Creating the first administrator

A new company has no admin yet, and nobody can become one through the website. Someone with server access runs:

```powershell
$env:ADMIN_EMAIL = "admin@yourcompany.com"
$env:ADMIN_NAME = "Your Name"
$env:ADMIN_PASSWORD = "a-long-password-of-at-least-12-characters"
npm run create-admin
```

Later administrators are promoted by an existing one from the Users page. The command is recorded in the audit log.

### Deploying on Render

1. Create a **Web Service** from the repository with **Root Directory** `server`, **Build Command** `npm install` and **Start Command** `npm start`.
2. Add environment variables: `DATABASE_URL` (a Neon connection string), `NODE_ENV=production` and `NODE_VERSION=22`.
3. Set the **Health Check Path** to `/health`.
4. From your own computer, point `DATABASE_URL` at the production database for one run of `npm run migrate`, `npm run seed` and `npm run seed-demo`.

The database schema is in `db/schema.sql`.

## Project layout

```
db/schema.sql           tables, audit triggers, role and recovery rules
server/src/authorize.js the one access decision
server/src/guard.js     calls it, answers 404, audits refusals
server/src/audit.js     the hash-chained, append-only log
server/src/routes/      auth, documents, grants, directory, admin
server/public/          the web pages (plain HTML, CSS and JavaScript)
server/scripts/         migrate, seed, seed-demo, audit-check, create-admin
server/tests/           automated tests
```

## What is not built

Groups and folders, sharing links for outsiders, email-based password reset, multi-factor login, malware scanning, restoring an earlier version in one click, permanent deletion, and the optional AI suggestion of who should see a document. Every one of these is explained in `THREATS.md` and the write-up, together with the known gaps.

## Known limits

- The free Render service sleeps when idle and has a small database (1 GB). Uploads are capped at 10 MB.
- A person who loses both their password and their recovery codes can not recover their account. That is by design.
- Whoever owns the database can read stored files and rewrite the audit log. The log is tamper-evident, not tamper-proof: see `THREATS.md`.