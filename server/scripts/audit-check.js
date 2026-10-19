require('dotenv').config();
const pool = require('../src/db');
const { verifyChain } = require('../src/audit');

async function main() {
  const result = await verifyChain();
  console.log(
    result.ok
      ? `Chain OK (${result.checked} entries)`
      : `CHAIN BROKEN at seq ${result.brokenAt}: ${result.reason}`
  );

  const { rows } = await pool.query(
    'SELECT seq, action, outcome, actor_email FROM audit_log ORDER BY seq DESC LIMIT 5'
  );
  console.table(rows);

  try {
    await pool.query(
      "UPDATE audit_log SET outcome = 'allowed' WHERE seq = (SELECT max(seq) FROM audit_log)"
    );
    console.log('WARNING: update succeeded, the audit log is NOT protected');
  } catch (err) {
    console.log('Tamper attempt blocked:', err.message);
  }
  await pool.end();
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});