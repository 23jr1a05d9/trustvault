# PROMPTS.md

## Reusable context
- `CLAUDE.md` holds the security rules I give my AI tool at the start of each session.

## Entries
(Each entry: date, what I asked, what it produced, what was wrong, what I did instead + commit link.)

### 2026-10-19: Login and registration routes
- **Asked:** for registration and login with argon2, cookie sessions and three roles.
- **Produced:** working routes with hashed passwords, hashed session tokens in the database, and rate limiting.
- **Wrong:** (1) registration returned "Email already registered", which lets anyone test whether a person has an account; (2) no login success or failure was written to the audit log, although the brief requires refused attempts to be recorded.
- **Fixed:** registration now gives the same reply either way, and every login, logout and registration is audited, with the real reason for a refusal. Commit: https://github.com/23jr1a05d9/trustvault/commit/794cd63