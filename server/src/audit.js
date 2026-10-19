const crypto = require('crypto');
const pool = require('./db');

const GENESIS = '0'.repeat(64); // "previous hash" of the very first row
const LOCK_KEY = 727001; // makes sure two writers never extend the chain at once

// JSON with keys sorted, so the same data always gives the same text.
function stable(value) {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
  if (value && typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + stable(value[k]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value === undefined ? null : value);
}

function computeHash(prevHash, e) {
  const payload = stable([
    prevHash,
    e.at,
    e.actor_id ?? null,
    e.actor_email ?? null,
    e.action,
    e.outcome,
    e.document_id ?? null,
    e.target_user_id ?? null,
    e.details ?? {},
    e.ip ?? null,
  ]);
  return crypto.createHash('sha256').update(payload).digest('hex');
}

async function insertEntry(client, entry) {
  // Only one transaction at a time may add to the chain.
  await client.query('SELECT pg_advisory_xact_lock($1)', [LOCK_KEY]);
  const last = await client.query('SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1');
  const prevHash = last.rows[0] ? last.rows[0].row_hash : GENESIS;

  const e = {
    at: new Date().toISOString(),
    actor_id: entry.actor_id ?? null,
    actor_email: entry.actor_email ?? null,
    action: entry.action,
    outcome: entry.outcome,
    document_id: entry.document_id ?? null,
    target_user_id: entry.target_user_id ?? null,
    details: entry.details ?? {},
    ip: entry.ip ?? null,
  };
  const rowHash = computeHash(prevHash, e);

  await client.query(
    `INSERT INTO audit_log
       (at, actor_id, actor_email, action, outcome, document_id, target_user_id, details, ip, prev_hash, row_hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [e.at, e.actor_id, e.actor_email, e.action, e.outcome, e.document_id,
     e.target_user_id, e.details, e.ip, prevHash, rowHash]
  );
}

// record(entry)         -> writes in its own transaction (use for refusals)
// record(entry, client) -> writes inside YOUR transaction, so the action and
//                          its audit row succeed or fail together
async function record(entry, client) {
  if (client) return insertEntry(client, entry);
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await insertEntry(c, entry);
    await c.query('COMMIT');
  } catch (err) {
    await c.query('ROLLBACK');
    throw err;
  } finally {
    c.release();
  }
}

// Walks the whole chain and recomputes every hash.
async function verifyChain() {
  const { rows } = await pool.query('SELECT * FROM audit_log ORDER BY seq ASC');
  let prev = GENESIS;
  for (const r of rows) {
    if (r.prev_hash !== prev) {
      return { ok: false, checked: rows.length, brokenAt: r.seq,
        reason: 'link broken: a row was removed or reordered before this one' };
    }
    const expected = computeHash(prev, {
      at: r.at.toISOString(),
      actor_id: r.actor_id,
      actor_email: r.actor_email,
      action: r.action,
      outcome: r.outcome,
      document_id: r.document_id,
      target_user_id: r.target_user_id,
      details: r.details,
      ip: r.ip,
    });
    if (expected !== r.row_hash) {
      return { ok: false, checked: rows.length, brokenAt: r.seq,
        reason: 'row contents were changed after it was written' };
    }
    prev = r.row_hash;
  }
  return { ok: true, checked: rows.length };
}

module.exports = { record, verifyChain };