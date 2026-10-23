# PROMPTS.md

I build TrustVault with Claude (Anthropic's AI assistant). This file records what I asked, what it produced, what was wrong, and what I did about it. Some entries were drafted with the AI's help from the real session history. I checked each one against what actually happened.

## Reusable context and working method
- `CLAUDE.md` (in the repo root) holds the security rules I give the AI at the start of a session: every document route goes through one `authorize()` decision, deny by default, refusals return 404 and are audited, permissions are read from the database on every request, and the client never supplies a role or an owner.
- After each piece of access-control code I check that its tests fail when the check is removed (for example, replacing the owner check with `if (true)`). A passing suite alone proves little.
- I ask the AI to explain any code line by line before I keep it. In the interview I need to explain every authorisation decision myself.

## Entries

### 2026-10-19: Login and registration routes (audit trail)
- **Asked:** for registration and login with argon2, cookie sessions and three roles.
- **Produced:** working routes with hashed passwords, hashed session tokens in the database, and rate limiting.
- **Wrong:** (1) registration returned "Email already registered", which lets anyone test whether a person has an account; (2) no login success or failure was written to the audit log, although the brief requires refused attempts to be recorded.
- **Fixed:** registration now gives the same reply either way, and every login, logout and registration is audited, with the real reason for a refusal kept only in the log. Commit: https://github.com/23jr1a05d9/trustvault/commit/794cd63

### 2026-10-19: Upload file-type check
- **Asked:** for upload validation that checks the real file type from its first bytes, not the extension.
- **Produced:** a route using the latest `file-type` package through a dynamic `import()`.
- **Wrong:** that package is ES-module only, and the dynamic import crashed under Jest (`ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG`), so every upload returned 500 and 26 tests failed. The tests found it, not me.
- **Fixed:** pinned `file-type@16.5.4`, which supports `require`. Commit: https://github.com/23jr1a05d9/trustvault/commit/1fbfe8c

### 2026-10-19: Where uploaded files are stored (access control)
- **Asked:** how to store files so they cannot be reached without authorisation.
- **Produced:** a plan to save files on disk under random names and serve them only through an authorised route.
- **Wrong:** the free Render web service wipes its disk on every restart and redeploy, so uploads would have vanished from the live site. I corrected this before building the upload route.
- **Fixed:** the file bytes go in a separate Postgres table, written in the same transaction as the document row and its audit row. No file paths exist, so path traversal is impossible. The cost is a 10 MB upload limit and the 1 GB free database. Commit: https://github.com/23jr1a05d9/trustvault/commit/1fbfe8c

### 2026-10-19: authorize() and its tests (access control)
- **Asked:** for one function that decides whether a user may read, download, edit, delete or share a document, deny by default, with tests.
- **Produced:** `authorize.js` plus 22 tests covering the owner, a stranger, an admin, read and edit grants, revoked grants, expired grants and a deleted document.
- **Wrong:** nothing in the logic, but a passing suite proves little on its own. I checked that the tests really guard the rule by replacing the owner check with `if (true)` and running them: 15 of 22 failed, including every "stranger may NOT" and "admin has no access by role alone" test. I then restored the line, and all 22 passed again.
- **Fixed / outcome:** no code change needed. This is evidence that the tests fail when the check is removed. Commit: https://github.com/23jr1a05d9/trustvault/commit/e57a624

### 2026-10-19: Where the access decision lives (access control)
- **Asked:** for document routes (upload, list, details, download, delete) that all use `authorize()`.
- **Produced:** a `guard()` helper written inside `documents.js` that calls `authorize()`, audits the refusal and answers 404.
- **Wrong:** when I added grants, the same decision was needed in a second router. Copying the helper would have created two doors that could drift apart, and a bug in one would be a hole. The AI had put the shared logic in a file-local function.
- **Fixed:** moved it to one `guard.js` that both routers import, so a single line decides and audits. Both the document and grant routes now depend on it. Commit: https://github.com/23jr1a05d9/trustvault/commit/fd5f89a

### 2026-10-19: The list query repeats the access rules (access control)
- **Asked:** for a document list that shows only what the caller can open.
- **Produced:** a SQL query with the owner-or-active-grant rule written inside it. The search feature later reused the same query.
- **Wrong:** this duplicates the logic in `authorize()`. If the two ever disagree, a document could appear in a list that the caller cannot open, or the reverse. The AI pointed this out itself when it wrote the code.
- **Fixed / outcome:** I kept the duplication on purpose. Filtering inside the SQL means documents the caller may not see are never fetched, never counted and never shown, while calling `authorize()` per row would fetch everything first. Tests pin the two together: a stranger, an outsider and an admin never see the document in the list or in search results, and a revoked grant disappears from the list on the next request. The risk is recorded in `THREATS.md`.

### 2026-10-19: Revoking a grant by id (access control)
- **Asked:** for owner-only revoke of a grant.
- **Produced:** an UPDATE that restricts the grant by both its id and the document id.
- **Wrong:** nothing found in the code, but the document-id condition is what stops an owner revoking another owner's grants by guessing ids.
- **Fixed / outcome:** no code change needed. The test "an owner can not revoke a grant that belongs to another document" guards it. Commit: https://github.com/23jr1a05d9/trustvault/commit/fd5f89a

### 2026-10-22: Approval gate for new accounts, and the admin screen that hid it (access control)
- **Asked:** a way for owners to share a document with many people by picking from a list, instead of typing each email.
- **Produced:** a people picker, plus a new `pending` role. New sign-ups start as `pending`, appear nowhere and can not be shared with until an administrator gives them a role. This stops someone registering with a lookalike name and appearing in every owner's list. The grant route also refuses pending and admin targets.
- **Wrong:** the admin screen's role dropdown did not include `pending`, so a waiting account looked like a viewer and choosing "viewer" changed nothing, because the browser already showed it. I found this by using the admin screen myself.
- **Fixed:** the dropdown now includes `pending`, the Users page shows how many accounts are waiting, and each one has an "Approve as viewer" button. Tests cover the directory and the refusal to share with pending or admin accounts. Commit: https://github.com/23jr1a05d9/trustvault/commit/f250e9b

### 2026-10-21: Forgot-password design (access control)
- **Asked:** for a forgot-password option.
- **Produced:** an admin-issued one-time reset link. The AI listed one risk and accepted it: the admin could use the link first and log in as that person.
- **Wrong:** that risk is not acceptable here. An admin taking over a viewer's account could read that person's important documents, which breaks the rule that admins never reach file contents. I rejected the design.
- **Fixed:** removed the admin reset completely and replaced it with self-service recovery codes: eight one-time codes, stored only as hashes and made from the account page after entering the current password. A reset needs the email and one code, uses the code up, and ends every other login. A test checks that no admin reset route exists. Email reset is not built: free Render blocks SMTP, and the common email service only sends to the account owner's own address without a verified domain. Commit: https://github.com/23jr1a05d9/trustvault/commit/f250e9b

### 2026-10-23: The edit permission did nothing (access control)
- **Asked:** for per-document permissions, read and edit, granted to named people.
- **Produced:** read and edit grants in the database and in `authorize()`, but no feature ever used the edit level. A person given edit access could do exactly what a reader could do: download.
- **Wrong:** the permission was stored and enforced as a word, but nothing behind it existed. I found this by logging in as a user with edit access and seeing only a Download button.
- **Fixed:** editors can now change a document's title and category and replace its file. A replaced file is kept as an earlier version that only the owner can see, so an edit never destroys the original. The edit is authorised before the upload is read and checked again inside the database transaction. The audit log records which fields changed, never the titles. Tests cover readers, strangers and admins being refused, revoked editors being refused on the next request, and that editors still cannot delete, share or see the history. Commit: https://github.com/23jr1a05d9/trustvault/commit/f250e9b