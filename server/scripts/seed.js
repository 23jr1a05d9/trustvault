require('dotenv').config();
const argon2 = require('argon2');
const pool = require('../src/db');

const users = [
  { email: 'admin@trustvault.test', name: 'Demo Admin', role: 'admin', password: 'AdminDemo#2026' },
  { email: 'owner@trustvault.test', name: 'Demo Owner', role: 'owner', password: 'OwnerDemo#2026' },
  { email: 'viewer@trustvault.test', name: 'Demo Viewer', role: 'viewer', password: 'ViewerDemo#2026' },
];

async function main() {
  for (const u of users) {
    const hash = await argon2.hash(u.password);
    await pool.query(
      `INSERT INTO users (email, name, password_hash, role)
       VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING`,
      [u.email, u.name, hash, u.role]
    );
  }
  console.log('Seeded', users.length, 'demo accounts.');
  await pool.end();
}

main().catch((err) => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});