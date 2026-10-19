# TrustVault rules for AI tools

1. Every route that touches a document calls `authorize(user, document, action)`. Deny by default.
2. The server decides. Never rely on the UI hiding something.
3. Unauthorised or missing documents return 404, so IDs cannot be probed.
4. Every action AND every refusal is written to the audit log, in the same transaction as the action.
5. Permissions are read from the database on every request. No caching, nothing in tokens.
6. Never accept `role` or `owner_id` from the request body.
7. Never use the user's filename on disk. Use random storage keys.
8. All SQL is parameterised. No string-building of queries.
9. Never reveal whether an email or document exists to someone who may not know.