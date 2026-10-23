const pool = require('./db');

const ACTIONS = ['read', 'download', 'edit', 'delete', 'share','history'];

// What each grant level allows. Delete and share are NOT here:
// only the owner can delete a document or change who has access.
const LEVEL_ALLOWS = {
  read: ['read', 'download'],
  edit: ['read', 'download', 'edit'],
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// THE one place that decides who may do what to a document.
// Deny by default: every path that is not explicitly allowed returns allowed:false.
async function authorize(user, documentId, action, db = pool) {
  const deny = (reason) => ({ allowed: false, reason, document: null });

  if (!user || !user.id) return deny('no_user');
  if (!ACTIONS.includes(action)) return deny('unknown_action');
  if (typeof documentId !== 'string' || !UUID_RE.test(documentId)) return deny('bad_id');

  // Always read fresh from the database. Nothing is cached, so a revoked
  // grant, an expired grant or a deleted document stops working at once.
  const { rows } = await db.query(
    `SELECT d.*, g.level AS grant_level
       FROM documents d
       LEFT JOIN grants g
         ON g.document_id = d.id
        AND g.user_id = $2
        AND g.revoked_at IS NULL
        AND (g.expires_at IS NULL OR g.expires_at > now())
      WHERE d.id = $1 AND d.deleted_at IS NULL`,
    [documentId, user.id]
  );
  const doc = rows[0];
  if (!doc) return deny('not_found');

  // The owner may do everything to their own document.
    if (doc.owner_id === user.id) return { allowed: true, via: 'owner', document: doc };

  // Everyone else needs a current grant that covers the action.
  // Note: being an admin gives NO access to document contents by itself.
  const allowed = LEVEL_ALLOWS[doc.grant_level];
  if (allowed && allowed.includes(action)) {
    return { allowed: true, via: 'grant:' + doc.grant_level, document: doc };
  }

  return deny('no_grant');
}

module.exports = { authorize, ACTIONS };