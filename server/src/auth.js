const crypto = require('crypto');
const pool = require('./db');

const COOKIE_NAME = 'tv_session';
const SESSION_HOURS = 8;

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  };
}

async function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_HOURS * 3600 * 1000);
  await pool.query(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
    [hashToken(token), userId, expires]
  );
  res.cookie(COOKIE_NAME, token, { ...cookieOptions(), expires });
}

async function destroySession(req, res) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (token) {
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(token)]);
  }
  res.clearCookie(COOKIE_NAME, cookieOptions());
}

// Runs before any protected route. Looks the user up in the database
// every single time, so nothing is cached and revocation is instant.
async function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Not logged in' });

  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.name, u.role
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now() AND u.is_active = true`,
    [hashToken(token)]
  );
  if (rows.length === 0) return res.status(401).json({ error: 'Not logged in' });

  req.user = rows[0];
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, createSession, destroySession };