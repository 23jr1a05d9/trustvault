const { authorize } = require('./authorize');
const { record } = require('./audit');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// The single door for every action on one existing document.
// Allowed -> returns the authorize() result.
// Refused -> writes an audit row, answers 404, returns null.
async function guard(req, res, action) {
  const id = req.params.id;
  const result = await authorize(req.user, id, action);
  if (!result.allowed) {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: `document.${action}`,
      outcome: 'denied',
      document_id: UUID_RE.test(id) ? id : null,
      details: { reason: result.reason, attempted_id: String(id).slice(0, 64) },
      ip: req.ip,
    });
    res.status(404).json({ error: 'Not found' }); // same answer as "does not exist"
    return null;
  }
  return result;
}

module.exports = { guard };