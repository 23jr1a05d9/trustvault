const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');
const pool = require('../db');
const { requireAuth, createSession, destroySession } = require('../auth');

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

// Used so a login for an unknown email takes as long as a real one.
let dummyHash;
async function getDummyHash() {
  if (!dummyHash) dummyHash = await argon2.hash('not-a-real-password');
  return dummyHash;
}

// Public registration. The role is NEVER read from the request.
// Every new account is a viewer. An admin can promote people later.
router.post('/register', limiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input. Password needs at least 10 characters.' });
  }
  const { email, name, password } = parsed.data;
  const hash = await argon2.hash(password);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, password_hash, role)
       VALUES ($1, $2, $3, 'viewer') RETURNING id, email, name, role`,
      [email, name, hash]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    throw err;
  }
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

  // Always run one password check, whether or not the user exists.
  const ok = await argon2.verify(user ? user.password_hash : await getDummyHash(), password);
  if (!user || !ok || !user.is_active) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  await createSession(res, user.id);
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
});

router.post('/logout', async (req, res) => {
  await destroySession(req, res);
  res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  res.json(req.user);
});

module.exports = router;