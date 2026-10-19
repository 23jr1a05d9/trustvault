# PROMPTS.md

## Reusable context
- `CLAUDE.md` holds the security rules I give my AI tool at the start of each session.

## Entries
(Each entry: date, what I asked, what it produced, what was wrong, what I did instead + commit link.)

### 2026-10-19: Upload file-type check
- **Asked:** for upload validation that checks the real file type from its first bytes, not the extension.
- **Produced:** a route using the latest `file-type` package through a dynamic `import()`.
- **Wrong:** that package is ES-module only, and the dynamic import crashed under Jest (`ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG`), so every upload returned 500 and 26 tests failed. The tests found it, not me.
- **Fixed:** pinned `file-type@16.5.4`, which supports `require`. Commit: https://github.com/23jr1a05d9/trustvault/commit/PASTE_HASH_HERE