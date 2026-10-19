require('dotenv').config();
const fs = require('fs');
const path = require('path');
const pool = require('../src/db');

async function main() {
  const file = path.join(__dirname, '..', '..', 'db', 'schema.sql');
  await pool.query(fs.readFileSync(file, 'utf8'));
  console.log('Schema applied.');

  const { rows } = await pool.query(
    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
  );
  console.log('Tables:', rows.map((r) => r.table_name).join(', '));
  await pool.end();
}

main().catch((err) => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});