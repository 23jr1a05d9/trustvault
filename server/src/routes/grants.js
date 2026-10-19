const express = require('express');
const { z } = require('zod');
const pool = require('../db');
const { requireAuth } = require('../auth');
const { guard } = require('../guard');
const { record } = require('../audit');

// mergeParams lets this router see :id from the path it is mounted on.
const router = express.Router({ mergeParams: true });
router.use(requireAuth);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const grantSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(200),
  level: z.enum(['read', 'edit']), // "owner" and "admin" can never be granted
  expires_at: z.string().refine((v) => !Number.isNaN(Date.parse(v))).optional(),
});

// GRANT (or change) access. Only the owner passes guard(..., 'share').
router.post('/', async (req, res) => {
  const result = await guard(req, res, 'share');
  if (!result) return;
  const doc = result.document;

  const parsed = grantSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Provide an email and a level of read or edit' });
  }
  const { email, level } = parsed.data;

  let expiresAt = null;
  if (parsed.data.expires_at) {
    expiresAt = new Date(parsed.data.expires_at);
    if (expiresAt <= new Date()) {
      return res.status(400).json({ error: 'Expiry must be in the future' });
    }
  }

  const refuse = async (reason, status, message, targetId) => {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'permission.grant',
      outcome: 'denied',
      document_id: doc.id,
      target_user_id: targetId ?? null,
      details: { reason, attempted_email: email },
      ip: req.ip,
    });
    return res.status(status).json({ error: message });
  };

  const found = await pool.query(
    'SELECT id, email, name FROM users WHERE email = $1 AND is_active = true',
    [email]
  );
  const target = found.rows[0];
  if (!target) return refuse('target_not_found', 400, 'Could not share with that person');
  if (target.id === req.user.id) {
    return refuse('self_grant', 400, 'You already own this document', target.id);
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Close any current grant first, so the history is kept and there is never
    // more than one active grant per person per document.
    const prev = await client.query(
      `UPDATE grants SET revoked_at = now()
        WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL
        RETURNING level`,
      [doc.id, target.id]
    );
    const ins = await client.query(
      `INSERT INTO grants (document_id, user_id, level, granted_by, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, level, expires_at, created_at`,
      [doc.id, target.id, level, req.user.id, expiresAt]
    );
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'permission.grant',
      outcome: 'allowed',
      document_id: doc.id,
      target_user_id: target.id,
      details: {
        level,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        previous_level: prev.rows[0] ? prev.rows[0].level : null,
      },
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.status(201).json({ ...ins.rows[0], user: target });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

// LIST who currently has access. Owner only.
router.get('/', async (req, res) => {
  const result = await guard(req, res, 'share');
  if (!result) return;
  const { rows } = await pool.query(
    `SELECT g.id, g.level, g.expires_at, g.created_at,
            u.id AS user_id, u.email, u.name
       FROM grants g JOIN users u ON u.id = g.user_id
      WHERE g.document_id = $1 AND g.revoked_at IS NULL
        AND (g.expires_at IS NULL OR g.expires_at > now())
      ORDER BY g.created_at DESC`,
    [result.document.id]
  );
  res.json(rows);
});

// REVOKE. Takes effect on the very next request, because every request
// reads the grants table. Nothing was issued that could outlive it.
router.delete('/:grantId', async (req, res) => {
  const result = await guard(req, res, 'share');
  if (!result) return;
  const doc = result.document;
  const { grantId } = req.params;

  const notFound = async () => {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'permission.revoke',
      outcome: 'denied',
      document_id: doc.id,
      details: { reason: 'grant_not_found', attempted_grant: String(grantId).slice(0, 64) },
      ip: req.ip,
    });
    return res.status(404).json({ error: 'Not found' });
  };
  if (!UUID_RE.test(grantId)) return notFound();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // "AND document_id = $2" is essential: without it an owner could revoke
    // grants on somebody else's document by guessing a grant id.
    const upd = await client.query(
      `UPDATE grants SET revoked_at = now()
        WHERE id = $1 AND document_id = $2 AND revoked_at IS NULL
        RETURNING user_id, level`,
      [grantId, doc.id]
    );
    if (upd.rowCount === 0) {
      await client.query('ROLLBACK');
      return notFound();
    }
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'permission.revoke',
      outcome: 'allowed',
      document_id: doc.id,
      target_user_id: upd.rows[0].user_id,
      details: { level: upd.rows[0].level },
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

module.exports = router;