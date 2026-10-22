require('dotenv').config();
const argon2 = require('argon2');
const pool = require('../src/db');
const { record } = require('../src/audit');

// Creates an admin from the command line, so no admin password ever sits in the repo.
async function main() {
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const name = (process.env.ADMIN_NAME || '').trim();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!email || !name || password.length < 12) {
    console.error('Set ADMIN_EMAIL, ADMIN_NAME and ADMIN_PASSWORD (at least 12 characters).');
    process.exit(1);
  }
  const hash = await argon2.hash(password);
  // An existing account is promoted. Its password is never overwritten.
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role) VALUES ($1, $2, $3, 'admin')
     ON CONFLICT (email) DO UPDATE SET role = 'admin', is_active = true
     RETURNING id`,
    [email, name, hash]
  );
  await record({
    actor_email: 'system:create-admin',
    action: 'admin.bootstrap',
    outcome: 'allowed',
    target_user_id: rows[0].id,
    details: { email },
  });
  console.log('Admin ready:', email);
  await pool.end();
}

main().catch((err) => {
  console.error('Failed:', err.message);
  process.exit(1);
});