const crypto = require('crypto');
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
  limit: Number(process.env.AUTH_RATE_LIMIT) || 20, // tests raise this; real use stays at 20
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
});

// The same rules as the registration form. The browser only shows hints;
// this is the check that counts.
const passwordRule = z
  .string()
  .min(6, 'too short') // change to 8 here AND MIN_LENGTH in public/app.js
  .max(128)
  .regex(/[A-Z]/)
  .regex(/[a-z]/)
  .regex(/[0-9]/)
  .regex(/[^A-Za-z0-9\s]/);

const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(200),
  name: z.string().trim().min(1).max(100),
  password: passwordRule,
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
      return res.status(400).json({
      error: 'Use a valid email and a password of at least 6 characters with an uppercase letter, a lowercase letter, a number and a special character.',
    });
  }
  const { email, name, password } = parsed.data;
  const hash = await argon2.hash(password);

  let created = null;
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, password_hash, role)
       VALUES ($1, $2, $3, 'pending') RETURNING id`,
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
    message: 'If this email was available, the account has been created and now waits for an administrator to approve it.',
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

const RULE_MESSAGE =
  'Use a password of at least 6 characters with an uppercase letter, a lowercase letter, a number and a special character.';

// ---------- recovery codes ----------
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 characters, no 0, O, 1 or I
function newCode() {
  let s = '';
  for (let i = 0; i < 12; i++) s += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]; // about 60 bits
  return s.slice(0, 4) + '-' + s.slice(4, 8) + '-' + s.slice(8);
}
const normalizeCode = (c) => String(c).toUpperCase().replace(/[^A-Z0-9]/g, '');
const hashCode = (c) => crypto.createHash('sha256').update(normalizeCode(c)).digest('hex');

// Forgot password. Open to anyone, but it needs the email AND a recovery code.
router.post('/reset-with-code', limiter, async (req, res) => {
  const { email, code, new_password: next } = req.body || {};
  const refuse = async (reason) => {
    await record({
      actor_email: typeof email === 'string' ? email.trim().toLowerCase().slice(0, 200) : null,
      action: 'auth.password_reset',
      outcome: 'denied',
      details: { reason },
      ip: req.ip,
    });
    // The same answer for an unknown email, a wrong code and a used code.
    return res.status(400).json({ error: 'The email or recovery code is not correct, or the code was already used.' });
  };
  if (typeof email !== 'string' || typeof code !== 'string') return refuse('bad_input');

  // Checked before the code is used, so a weak password never burns a code.
  const rule = passwordRule.safeParse(next);
  if (!rule.success) return res.status(400).json({ error: RULE_MESSAGE });

  const normalized = normalizeCode(code);
  if (!/^[A-Z2-9]{12}$/.test(normalized)) return refuse('malformed_code');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // One statement checks the code AND uses it up, so it can never work twice.
    const claim = await client.query(
      `UPDATE recovery_codes AS rc SET used_at = now()
         FROM users AS u
        WHERE rc.user_id = u.id AND u.email = $1 AND u.is_active = true
          AND rc.code_hash = $2 AND rc.used_at IS NULL
        RETURNING u.id AS user_id, u.email`,
      [email.trim().toLowerCase(), hashCode(normalized)]
    );
    if (claim.rowCount === 0) {
      await client.query('ROLLBACK');
      return refuse('unknown_email_or_code');
    }
    const { user_id: userId, email: userEmail } = claim.rows[0];
    const hash = await argon2.hash(rule.data);
    await client.query('UPDATE users SET password_hash = $2 WHERE id = $1', [userId, hash]);
    await client.query('DELETE FROM sessions WHERE user_id = $1', [userId]); // every old login ends
    const left = await client.query(
      'SELECT count(*)::int AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL', [userId]
    );
    await record({
      actor_id: userId,
      actor_email: userEmail,
      action: 'auth.password_reset',
      outcome: 'allowed',
      details: { codes_left: left.rows[0].n }, // the code itself is never logged
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.json({ ok: true, codes_left: left.rows[0].n });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

// A logged-in person changes their own password.
router.post('/change-password', limiter, requireAuth, async (req, res) => {
  const { current_password: current, new_password: next } = req.body || {};
  const rule = passwordRule.safeParse(next);
  if (typeof current !== 'string' || !current || !rule.success) {
    return res.status(400).json({ error: 'Enter your current password and a new one. ' + RULE_MESSAGE });
  }
  if (current === next) return res.status(400).json({ error: 'Choose a password different from the current one.' });

  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  if (!(await argon2.verify(rows[0].password_hash, current))) {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'auth.password_change',
      outcome: 'denied',
      details: { reason: 'wrong_current_password' },
      ip: req.ip,
    });
    return res.status(400).json({ error: 'Your current password is not correct.' });
  }

  const hash = await argon2.hash(rule.data);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE users SET password_hash = $2 WHERE id = $1', [req.user.id, hash]);
    await client.query('DELETE FROM sessions WHERE user_id = $1', [req.user.id]); // all logins end, including this one
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'auth.password_change',
      outcome: 'allowed',
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  await createSession(res, req.user.id); // this browser gets a fresh login
  res.json({ ok: true });
});

// How many unused codes the logged-in person has left.
router.get('/recovery-codes', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT count(*)::int AS remaining FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL',
    [req.user.id]
  );
  res.json({ remaining: rows[0].remaining });
});

// Make a fresh set of 8 codes, replacing any older ones. Needs the current
// password, so a stolen session alone can not create a way to reset it.
router.post('/recovery-codes', limiter, requireAuth, async (req, res) => {
  const current = req.body && req.body.current_password;
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  const ok = typeof current === 'string' && current.length > 0 && (await argon2.verify(rows[0].password_hash, current));
  if (!ok) {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'auth.recovery_codes.generate',
      outcome: 'denied',
      details: { reason: 'wrong_current_password' },
      ip: req.ip,
    });
    return res.status(400).json({ error: 'Your current password is not correct.' });
  }

  const codes = Array.from({ length: 8 }, newCode);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [req.user.id]);
    for (const c of codes) {
      await client.query('INSERT INTO recovery_codes (code_hash, user_id) VALUES ($1, $2)', [hashCode(c), req.user.id]);
    }
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'auth.recovery_codes.generate',
      outcome: 'allowed',
      details: { count: codes.length }, // the codes themselves are never logged
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  res.set('Cache-Control', 'no-store');
  res.status(201).json({ codes });
});
module.exports = router;