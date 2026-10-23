# TrustVault write-up

## What I built

TrustVault is a document-sharing website where the wrong person can not reach a file and I can show who did. It is a Node.js and Express server with a PostgreSQL database, and a web page written in plain HTML, CSS and JavaScript. It is live at https://trustvault-demo-li4x.onrender.com, with a separate development database.

The ten required features are all there:

- Login with three roles (admin, owner, viewer), plus a waiting state called `pending` for new accounts.
- Upload, categories, search by name, owner, category and date, and delete.
- Per-document `read` and `edit` permissions for named people, with optional expiry.
- Owners can grant and take back access, to several people at once from a checklist.
- Strangers can not read, download, change or delete a document.
- An audit trail of uploads, downloads, edits, deletions, permission changes, logins and refusals.
- Upload checks (real file type, size limit).
- An admin view with activity, accounts worth noticing, user management and CSV export.
- Automated tests showing one user can not reach another's documents ([167] tests in [11] suites).

I also added things the list does not ask for: editing with kept versions, an approval step for new accounts, self-service password reset with recovery codes, change password, and a hash-chained audit log that the admin can re-verify.

## How the permissions work, in my own words

There are two layers. A **role** says what kind of person you are: an owner can upload and share, an admin runs the system, a viewer only reads. A **grant** says which specific document you were given, at which level. A role never opens a document by itself.

Every request that touches a document goes through one function, `authorize()`. It reads the database each time. It allows the action only if the person owns the document or holds a grant that is not revoked and not expired and that covers the action. Everything else is refused. If you are refused, the server answers "not found" (the same as if the document did not exist), so ids can not be probed, and it writes the refusal to the audit log.

Because nothing is cached and no link or token carries permissions, taking access away works on the very next request.

The admin is deliberately kept away from file contents. An admin sees what happened (who opened what, and when) but not what is inside, and can not reset anyone's password, because a reset link would let the admin log in as that person.

## Where the access decision is made

`server/src/authorize.js` decides, and `server/src/guard.js` calls it for every document route. The download route is the line `guard(req, res, 'download')` in `routes/documents.js`. If I removed it, the route would not have a document to send and the "never granted access" tests would fail.

## What I deliberately did not build

- **Groups and folder inheritance.** Every grant is per document. Groups add another place where access can leak.
- **Sharing links for outsiders.** A link outlives a revoke, which would break the rule that taking access away works immediately.
- **Email-based password reset.** Free Render blocks outgoing email ports, and the common email service only sends to the account owner's own address unless a domain is verified. Recovery codes work without email, and no admin can use them.
- **Multi-factor login, malware scanning, encryption of stored files, permanent deletion and a one-click restore of earlier versions.**
- **The AI suggestion of who should see a document.** I chose not to build it, so there is no risk of a machine widening access.

## How I used AI, and where it was wrong

I built this with Claude, an AI assistant, and I say so plainly: it wrote most of the code. My job was to direct it, test it and catch it being wrong. `PROMPTS.md` has the full record. The main places it was wrong:

- **Registration revealed which emails existed, and logins were not audited.** Fixed so every login, logout and refusal is recorded.
- **A file-type package crashed the tests** and made every upload fail. I pinned an older version.
- **The plan to store files on disk** would have lost them on the free host. Files are now stored in the database.
- **The shared access check was written inside one file**, which would have left two doors that could drift apart. It now lives in one place.
- **The edit permission did nothing.** It was stored and checked, but no feature used it. I found this by logging in as an editor and seeing only a Download button.
- **The first forgot-password design let an admin take over any account.** I rejected it and replaced it with recovery codes.
- **The admin screen hid the `pending` role**, so new accounts looked approved. Fixed with an Approve button.

To check the AI's access-control code, I remove one check at a time and run the tests, expecting them to fail. [CONFIRM: the one I ran and its result, for example "Replacing the owner check with `if (true)` made 15 of 22 authorisation tests fail."]

## What is unfinished or weak

- **The audit log is tamper-evident, not tamper-proof.** The database refuses changes and every row is chained to the one before, but whoever owns the database could remove those protections and rewrite history, and the newest rows could be removed without breaking the chain. A restricted database user and storing the chain head elsewhere would fix this.
- **The demo accounts are public**, as the challenge requires, so anyone can lock them. A real deployment would delete them.
- **A person who loses both password and recovery codes can not get back in**, and an owner's documents would then be stranded. Ownership transfer is not built.
- **Rate limiting is per address and held in memory**, and it is not covered by a test.
- **The password minimum is 6 characters**, as I specified. 8 would be safer.
- **The free host sleeps when idle**, so the first request can take about a minute. Uploads are limited to 10 MB.
- [CONFIRM: anything I did not finish or test, listed honestly before submitting.]

The full list of threats, with the test that proves each defence and the risks I accepted, is in `THREATS.md`.