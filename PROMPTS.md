# PROMPTS.md

## Reusable context
- `CLAUDE.md` holds the security rules I give my AI tool at the start of each session.
- Some entries in this file were drafted with AI help from the real session history. I checked each against what happened and filled in the results myself.

## Entries
(Each entry: date, what I asked, what it produced, what was wrong, what I did instead + commit link.)

### 2026-10-19: Upload file-type check
- **Asked:** for upload validation that checks the real file type from its first bytes, not the extension.
- **Produced:** a route using the latest `file-type` package through a dynamic `import()`.
- **Wrong:** that package is ES-module only, and the dynamic import crashed under Jest (`ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG`), so every upload returned 500 and 26 tests failed. The tests found it, not me.
- **Fixed:** pinned `file-type@16.5.4`, which supports `require`. Commit:https://github.com/23jr1a05d9/trustvault/commit/1fbfe8c

### 2026-10-19: authorize() and its tests (access control)
- **Asked:** for one function that decides whether a user may read, download, edit, delete or share a document, deny by default, with tests.
- **Produced:** `authorize.js` plus 22 tests covering the owner, a stranger, an admin, read and edit grants, revoked grants, expired grants and a deleted document.
- **Wrong:** nothing in the logic, but a passing suite proves little on its own. I checked that the tests really guard the rule by replacing the owner check with `if (true)` and running them: 15 of 22 failed, including every "stranger may NOT" and "admin has no access by role alone" test. I then restored the line, and all 22 passed again.
- **Fixed / outcome:** no code change needed. Evidence that the tests fail when the check is removed. Commit: https://github.com/23jr1a05d9/trustvault/commit/e57a624

### 2026-10-19: Where the access decision lives (access control)
- **Asked:** for document routes (upload, list, details, download, delete) that all use `authorize()`.
- **Produced:** a `guard()` helper written inside `documents.js` that calls `authorize()`, audits the refusal and answers 404.
- **Wrong:** when I added grants, the same decision was needed in a second router. Copying the helper would have created two doors that could drift apart, and a bug in one would be a hole. The AI had put the shared logic in a file-local function.
- **Fixed:** moved it to one `guard.js` that both routers import, so a single line decides and audits. Both document and grant routes now depend on it. Commit: https://github.com/23jr1a05d9/trustvault/commit/fd5f89a

### 2026-10-19: The list query repeats the access rules (access control)
- **Asked:** for a document list that shows only what the caller can open.
- **Produced:** a SQL query with the owner-or-active-grant rule written inside it.
- **Wrong:** this duplicates the logic in `authorize()`. If the two ever disagree, a document could appear in a list that the caller cannot open, or the reverse. The AI pointed this out itself when it wrote the code.
- **Fixed / outcome:** [FILL: what you decided. For example "accepted for now and listed in THREATS.md, with tests that a stranger, an outsider and an admin never see the document in their list", or the fix you made.]

### 2026-10-19: Revoking a grant by id (access control)
- **Asked:** for owner-only revoke of a grant.
- **Produced:** an UPDATE that restricts the grant by both its id and the document id.
- **Wrong:** nothing found, but this is the line that stops an owner revoking another owner's grants by guessing ids. I removed `AND document_id = $2` and ran the tests: [FILL: number of tests that failed]. I then restored it, and all 73 passed.
- **Fixed / outcome:** no code change needed. The test "an owner can not revoke a grant that belongs to another document" guards it. Commit: https://github.com/23jr1a05d9/trustvault/commit/fd5f89a