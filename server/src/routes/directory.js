const express = require('express');
const pool = require('../db');
const { requireAuth } = require('../auth');
const { record } = require('../audit');

const router = express.Router();
router.use(requireAuth);

// Only owners may look people up, because only owners can share documents.
router.use(async (req, res, next) => {
  if (req.user.role === 'owner') return next();
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'directory.list',
    outcome: 'denied',
    details: { reason: 'role_not_allowed', role: req.user.role },
    ip: req.ip,
  });
  res.status(403).json({ error: 'Forbidden' });
});

// People a document can be shared with: active accounts an administrator has
// approved (viewer or owner). New sign-ups ('pending'), admins and locked
// accounts never appear, and nobody sees their own entry.
router.get('/', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, email, role FROM users
      WHERE is_active = true AND role IN ('viewer', 'owner') AND id <> $1
      ORDER BY name, email LIMIT 500`,
    [req.user.id]
  );
  res.json(rows);
});

module.exports = router;