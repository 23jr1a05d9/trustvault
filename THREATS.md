# THREATS.md

How I think TrustVault could be broken, what I did about each way, and what I knowingly left open.

**How to read it.** Each entry has the attack, my defence, the proof, and the risk that remains. "Tested" means an automated test in `server/tests` checks it. "Verified by hand" means I checked it myself without a test. "By design" means it follows from how the code is built, with no test.

## Where the access decision is made

- `server/src/authorize.js` is the only function that decides whether a person may do something to a document. It reads the database on every call, denies by default, and treats only the owner or a current (not revoked, not expired) grant as allowed.
- `server/src/guard.js` calls it for every route that touches one existing document, answers **404** when refused (the same answer as "does not exist"), and writes an audit row for the refusal.
- Download is `guard(req, res, 'download')` in `routes/documents.js`. If that line is removed, the route no longer has a document to send and the "never granted access" tests fail.
- Two places repeat the rule on purpose, in SQL: the document list and search. Entry 3 explains why.

---

## A. Reaching a document you were not given

**1. Reaching a document by its id** (guessing, replaying, or trying other routes)
- **Defence:** every document route (details, download, edit, replace, delete, grants, version history) goes through `guard()`. Ids are random UUIDs. A refused request gets 404, so an id can not be probed. Malformed ids are refused without touching the database.
- **Proof:** Tested (`authorize.test.js`, `documents.test.js`, `grants.test.js`, `edit.test.js`: strangers, outsiders and admins are refused on every action and the document is unchanged afterwards).
- **Residual:** none known.

**2. An administrator reading file contents**
- **Defence:** the admin role grants no document access. Admins get 404 like any stranger. People can only share with approved viewers and owners, never with admins or pending accounts.
- **Proof:** Tested ("admin has no access by role alone", the admin cases in `documents.test.js`, `directory.test.js`).
- **Residual:** someone with direct database access (including me, as the database owner) can read the stored file bytes. Files are not encrypted at the application level. Accepted.

**3. Leaks through the document list and search**
- **Defence:** the permission rule is inside the SQL, so unauthorised documents are never fetched, counted or shown through any filter. Search text is parameterised and `%`, `_` and `\` match literally. Dates, limits and repeated parameters are validated.
- **Proof:** Tested (`search.test.js`: a stranger searching the exact title gets nothing and a count of 0; wildcard characters; revoked documents leave the list on the next request).
- **Residual:** the list and `authorize()` express the same rule twice. If they ever disagree, a document could show in a list that the caller cannot open, or the reverse. I kept the SQL version because calling `authorize()` per row would fetch every document first. The tests above pin the two together.

**4. Role or owner chosen by the client** (mass assignment)
- **Defence:** `role` and `owner_id` are never read from a request. New accounts are `pending`. Upload takes the owner from the logged-in user. The admin update accepts only `role` and `is_active` and rejects other fields. The document edit accepts only `title` and `category`.
- **Proof:** Tested (`password.test.js` sends `role: admin` and the account stays pending; `documents.test.js` sends `owner_id` and `role` in the upload form; `edit.test.js` sends `owner_id` in an edit; `admin.test.js`).
- **Residual:** none known.

**5. Abusing sharing**
- **Defence:** only the owner passes the `share` action. An editor can not re-share. Self-grants are refused. Only `read` and `edit` exist as levels. A grant to a different document's grant id is refused because the revoke is restricted by document id. Pending, admin and locked accounts can not be shared with.
- **Proof:** Tested (`grants.test.js`, `directory.test.js`).
- **Residual:** an owner can share with any approved person. That is the purpose of sharing.

**6. Abusing the edit permission**
- **Defence:** an editor can change the title and category and replace the file, nothing else. Delete, share and version history stay owner-only (no grant level includes them). The replaced file is kept as an earlier version, so an edit never destroys the original. The edit is checked before the upload is read, and checked again inside the database transaction.
- **Proof:** Tested (`edit.test.js`: readers, strangers and admins are refused; revoked editors are refused on the next request; editors can not delete, share or read the history; a non-PDF replacement is refused and changes nothing).
- **Residual:** an editor can replace a file with a bad one. The owner can download the original from the history.

**7. Deleted documents**
- **Defence:** deletion is soft. A deleted document is unreachable for everyone, including its owner, in every route.
- **Proof:** Tested (`authorize.test.js`, `documents.test.js`, `edit.test.js`).
- **Residual:** the bytes stay in the database and are never purged. Retention and permanent deletion are not built. Accepted.

---

## B. Taking access away

**8. Access that outlives its removal**
- **Defence:** nothing is cached and nothing is issued that could outlive a grant: no tokens carry permissions and no download links exist. Every request reads the grants table.
- **Proof:** Tested (revocation on the very next request in `authorize.test.js` and `documents.test.js`; expiry; an editor revoked mid-way in `edit.test.js`; a role change taking effect on the next request in `admin.test.js`).
- **Residual:** the cost is one database lookup per request.

**9. Revoking during a download or an edit**
- **Defence:** a replace re-checks access inside the database transaction while holding a lock on the document.
- **Proof:** By design.
- **Residual:** a revoke that commits in the few milliseconds after a download's check does not stop that single download. Accepted.

**10. Stale logins**
- **Defence:** sessions live in the database. Locking an account, changing a password and using a recovery code each delete that person's sessions in the same transaction.
- **Proof:** Tested (`admin.test.js` locking, `recovery.test.js` for reset and change).
- **Residual:** none known.

---

## C. Accounts and sessions

**11. Password guessing**
- **Defence:** passwords are hashed with argon2. Login, registration and the other password routes are limited to 20 attempts per 15 minutes per address.
- **Proof:** By design (the limiter is not covered by an automated test).
- **Residual:** the limit is per address and held in memory, so it resets on restart and does not stop an attack spread over many addresses. There is no account lockout, on purpose, because lockout lets an attacker lock other people out. The minimum password length is 6 (a product requirement) and 8 would be safer. It is one constant on each side.

**12. Finding out who has an account**
- **Defence:** login gives the same error for an unknown email and a wrong password, and does the same amount of password work either way. Registration gives the same reply whether or not the email is taken. A failed password reset gives one answer for an unknown email, a wrong code and a used code.
- **Proof:** Tested for the reset (`recovery.test.js`). Verified by hand for login and registration.
- **Residual:** owners can see the approved people in the sharing list. That is needed to share.

**13. Stolen session cookie**
- **Defence:** the cookie is random (256 bits), `HttpOnly`, `Secure` and `SameSite=Strict`. Only a hash of it is stored. Sessions last 8 hours and end on logout.
- **Proof:** Verified by hand on the live site (the `Set-Cookie` header).
- **Residual:** a stolen cookie works until it expires or the person logs out. It is not tied to a device.

**14. Forgotten password**
- **Defence:** a person resets their own password with their email plus one of eight recovery codes they saved earlier. Each code is about 60 bits, stored only as a hash, works once, and is used up by the same statement that checks it. A weak new password is refused before the code is used. A reset ends every other login.
- **Why not an admin reset:** an admin who issues a reset link could use it first and then read that person's documents. I dropped that design (see `PROMPTS.md`). There is no admin reset route, and a test checks that.
- **Proof:** Tested (`recovery.test.js`).
- **Residual:** someone who loses both the password and the codes can not recover the account, by design, and an owner's documents would then be stranded (ownership transfer is not built). Anyone holding a code and the email can reset that password, so codes must be kept safe. Email reset is not built: free Render blocks outbound SMTP, and the usual email service only delivers to the account owner's own address unless a domain is verified.

**15. Open registration**
- **Defence:** a new account is `pending`. It can log in but can not upload, appears in nobody's sharing list and can not be shared with until an admin gives it a role. This also stops a lookalike name appearing in owners' lists.
- **Proof:** Tested (`password.test.js`, `directory.test.js`).
- **Residual:** anyone can create pending accounts, so an admin has to review the list.

**16. Public demo accounts**
- **Defence:** the challenge requires demo credentials to be public. The demo admin can approve accounts, change roles, lock users and export the user list and activity, but it can not read file contents.
- **Proof:** By design.
- **Residual:** anyone with the demo credentials can lock the demo accounts or change their passwords and so lock out later visitors. Recovery needs database access. A real deployment would delete the demo accounts. Accepted.

---

## D. Uploads

**17. Disguised, oversized and oddly named files**
- **Defence:** the real type is read from the file's first bytes and must be PDF, PNG, JPG, DOCX or XLSX (the claimed type and extension are ignored). The limit is 10 MB and one file per upload (413 when over). The original filename is only for display, with control characters and slashes replaced. The file is stored as bytes in the database, so no filename ever becomes a path.
- **Proof:** Tested (`documents.test.js`: text sent as a PDF, HTML sent as a PNG, a file over 10 MB; `edit.test.js` for replacements).
- **Residual:** none known.

**18. An uploaded file used against another person**
- **Defence:** a file is only returned as a download (`Content-Disposition: attachment`) with the detected type, `nosniff` and `no-store`, and the interface never renders uploaded content.
- **Proof:** Tested (the download headers in `documents.test.js`).
- **Residual:** none known.

**19. Valid but malicious files** (macros, scripts inside PDFs, compressed-file tricks in DOCX and XLSX)
- **Defence:** none beyond type checking and forced download. Files are not scanned or opened by the server.
- **Proof:** By design.
- **Residual:** the risk moves to whoever opens the file. Accepted, and listed in the write-up.

**20. Memory exhaustion by uploads**
- **Defence:** uploads are buffered in memory (at most 10 MB), but only after login and the owner-role or edit check, so strangers can not make the server buffer anything.
- **Proof:** By design.
- **Residual:** many large simultaneous uploads by logged-in owners could use a lot of memory. There is no per-user upload limit. Accepted.

---

## E. The audit trail

**21. Quietly altering the audit log**
- **Defence:** three layers. The database refuses `UPDATE`, `DELETE` and `TRUNCATE` on the log with triggers. Every row stores a hash of the previous row, so an edit or a missing row breaks the chain. An admin can re-check the whole chain at any time, and the overview checks it on every load.
- **Proof:** Tested (the chain verifies after many different actions across the suites). Verified by hand (`npm run audit-check` shows the tamper attempt being refused).
- **Residual:** whoever owns the database can remove the triggers and rewrite rows (and the newest rows could be deleted without breaking the chain), because the application connects with full rights and the chain head is not stored anywhere outside the database. A restricted insert-only database role and anchoring the chain head elsewhere are not built. This is the biggest known gap in the audit design.

**22. Actions without a record**
- **Defence:** the audit row is written in the same transaction as the action. A download writes its audit row before any byte is sent. If the audit write fails, the request fails.
- **Proof:** Tested (the "is audited" tests; failing closed was seen when the database was unreachable: the request returned an error and nothing changed).
- **Residual:** if the log can not be written, the system stops working rather than carrying on unrecorded. Accepted.

**23. Refused attempts that leave no trace**
- **Defence:** every refusal is recorded, including document 404s, failed logins, refused admin and directory access, refused edits and wrong current passwords, with the reason.
- **Proof:** Tested (`documents.test.js`, `edit.test.js`, `admin.test.js`, `directory.test.js`, `recovery.test.js`, `export.test.js`).
- **Residual:** none known.

**24. Secrets and hostile text in the log**
- **Defence:** recovery codes, reset secrets, document titles and file contents are never written to the log. Edits record which fields changed, never their values. Text typed by an attacker (such as an email on a failed login) is stored as data, truncated, and shown with `textContent`.
- **Proof:** Tested (`recovery.test.js` and `edit.test.js` check that codes and titles never appear in the log).
- **Residual:** none known.

---

## F. Admin and export

**25. Admin overreach**
- **Defence:** an admin can not change or lock their own account, so the last admin can never be removed. Role changes record the before and after. Locking ends sessions at once. Admins can not read file contents and can not reset passwords.
- **Proof:** Tested (`admin.test.js`).
- **Residual:** one admin can promote another, with no second approval. Accepted and listed below.

**26. Export as a way to leak data**
- **Defence:** exports are admin-only, written to the audit log before any data is sent, capped at 10,000 rows, and never include password data, file contents or document titles. Cells that start with `=`, `+`, `-` or `@` get a leading apostrophe so a spreadsheet will not run them as formulas.
- **Proof:** Tested (`export.test.js`).
- **Residual:** once the CSV is on an admin's computer the application no longer controls it.

---

## G. Web attacks

**27. Cross-site scripting**
- **Defence:** the interface builds the page with `textContent` and never with `innerHTML`, and Helmet's content security policy only allows scripts from the site itself. Uploaded files are never rendered.
- **Proof:** Tested (`ui.test.js` checks the policy).
- **Residual:** the policy allows inline styles (a Helmet default).

**28. Cross-site request forgery and CORS**
- **Defence:** the session cookie is `SameSite=Strict`, so other sites can not make the browser send it. No cross-origin access is enabled.
- **Proof:** By design (no automated test).
- **Residual:** there are no CSRF tokens, so protection rests on the browser honouring `SameSite`. Accepted.

**29. SQL injection**
- **Defence:** every value goes in as a query parameter. The only text added to a query is fixed fragments written in the code. Filters are validated first.
- **Proof:** Tested (injection text in search and admin filters in `search.test.js` and `admin.test.js`).
- **Residual:** none known.

**30. Headers, exposed files and error leakage**
- **Defence:** Helmet sets the security headers. Only the `public` folder is served. Request bodies are limited to 10 KB. Errors return a generic message and the details stay in the server log.
- **Proof:** Tested (`ui.test.js` checks that `/.env`, `/package.json` and `/src/app.js` are not served).
- **Residual:** none known.

---

## H. Operations

**31. Secrets in the repository**
- **Defence:** `.env` is ignored by Git. The production database address lives only in Render's environment variables. Production and development use separate databases.
- **Proof:** Verified by hand before the repository is made public (a search of the full history for the database host name).
- **Residual:** the demo passwords are in the README by requirement (entry 16).

**32. Dependencies**
- **Defence:** `npm audit` reports warnings in test tooling. Render installs with `NODE_ENV=production`, which skips development dependencies.
- **Proof:** By design.
- **Residual:** I have not reviewed the runtime dependencies beyond installing current versions.

**33. Availability**
- **Defence:** none beyond the rate limit. The free Render service sleeps when idle (the first request can take about a minute) and the free database has limits.
- **Proof:** By design.
- **Residual:** accepted for a challenge deployment.

---

## Knowingly not built

- **Groups and folder inheritance.** Every grant is per document, with a checklist for sharing with many people. Groups would add another place where access can leak.
- **Sharing links for people outside the company.** A link outlives a revoke, which breaks the third standard. Outside people can have an account instead.
- **Email-based password reset**, because of the hosting limits above.
- **Restoring an earlier version in one click.** The owner can download it and upload it again.
- **Two-person approval for new admins**, multi-factor login, malware scanning, application-level encryption at rest, an insert-only audit database role and external anchoring of the chain head.
- **Permanent deletion and retention rules.**
- **An AI suggestion of who should see a document.** If I add it, it must never widen access on its own, and both the suggestion and the person's decision must go in the audit.

## How I checked that the tests test something

I break one check at a time, run the suite, confirm it fails, and restore the check.

| Change | Result |
|---|---|
| Owner check in `authorize()` replaced with `if (true)` | 15 of 22 tests in `authorize.test.js` failed, including every "stranger may NOT" and "admin has no access by role alone" test |