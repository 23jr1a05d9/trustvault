const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');
const pool = require('../db');
const { requireAuth, createSession, destroySession } = require('../auth');
const { record } = require('../audit');

const router = express.Router();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
});

const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(200),
  name: z.string().trim().min(1).max(100),
  password: z.string().min(10).max(128),
});

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().max(200),
  password: z.string().min(1).max(128),
});

let dummyHash;
async function getDummyHash() {
  if (!dummyHash) dummyHash = await argon2.hash('not-a-real-password');
  return dummyHash;
}

// The role is NEVER read from the request. New accounts are always viewers.
// The reply is identical whether or not the email was already taken, so
// nobody can use this form to find out who has an account.
router.post('/register', limiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input. Password needs at least 10 characters.' });
  }
  const { email, name, password } = parsed.data;
  const hash = await argon2.hash(password);

  let created = null;
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, password_hash, role)
       VALUES ($1, $2, $3, 'viewer') RETURNING id`,
      [email, name, hash]
    );
    created = rows[0];
  } catch (err) {
    if (err.code !== '23505') throw err; // 23505 = email already exists
  }

  await record({
    actor_id: created ? created.id : null,
    actor_email: email,
    action: 'auth.register',
    outcome: created ? 'allowed' : 'denied',
    details: created ? {} : { reason: 'email_exists' },
    ip: req.ip,
  });

  res.status(201).json({
    ok: true,
    message: 'If this email was available, the account has been created. Please log in.',
  });
});

router.post('/login', limiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });
  const { email, password } = parsed.data;

  const { rows } = await pool.query(
    'SELECT id, email, name, role, password_hash, is_active FROM users WHERE email = $1',
    [email]
  );
  const user = rows[0];

  const ok = await argon2.verify(user ? user.password_hash : await getDummyHash(), password);
  if (!user || !ok || !user.is_active) {
    // The caller learns nothing. The audit log records the real reason.
    await record({
      actor_id: user ? user.id : null,
      actor_email: email,
      action: 'auth.login',
      outcome: 'denied',
      details: { reason: !user ? 'unknown_email' : !ok ? 'bad_password' : 'inactive' },
      ip: req.ip,
    });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  await createSession(res, user.id);
  await record({
    actor_id: user.id,
    actor_email: user.email,
    action: 'auth.login',
    outcome: 'allowed',
    ip: req.ip,
  });
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
});

router.post('/logout', requireAuth, async (req, res) => {
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'auth.logout',
    outcome: 'allowed',
    ip: req.ip,
  });
  await destroySession(req, res);
  res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  res.json(req.user);
});

module.exports = router;