const express = require('express');
const { z } = require('zod');
const pool = require('../db');
const { requireAuth } = require('../auth');
const { record, verifyChain } = require('../audit');

const router = express.Router();
router.use(requireAuth);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EXPORT_LIMIT = 10000;

// Every route below is admin-only. Refused attempts are audited too.
async function adminOnly(req, res, next) {
  if (req.user.role === 'admin') return next();
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'admin.access',
    outcome: 'denied',
    details: { reason: 'role_not_allowed', role: req.user.role, path: String(req.originalUrl).slice(0, 200) },
    ip: req.ip,
  });
  res.status(403).json({ error: 'Forbidden' });
}
router.use(adminOnly);

const GROUPS = {
  documents: 'document.%',
  permissions: 'permission.%',
  auth: 'auth.%',
  admin: 'admin.%',
};

const dateStr = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((v) => !Number.isNaN(Date.parse(v)));
const auditSchema = z.object({
  group: z.enum(['documents', 'permissions', 'auth', 'admin']).optional(),
  action: z.string().regex(/^[a-z_]+(\.[a-z_]+)*$/).max(50).optional(),
  outcome: z.enum(['allowed', 'denied']).optional(),
  actor: z.string().trim().max(100).optional(),
  document_id: z.string().regex(UUID_RE).optional(),
  from: dateStr.optional(),
  to: dateStr.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).max(100000).default(0),
});

const like = (s) => '%' + s.replace(/[\\%_]/g, '\\$&') + '%';

// Builds the WHERE part from validated filters. Every value goes in as a $n
// parameter, so nothing typed by the caller is ever added to the SQL text.
function auditWhere(f, params) {
  const where = [];
  const next = (v) => { params.push(v); return '$' + params.length; };
  if (f.group) where.push(`action LIKE ${next(GROUPS[f.group])}`);
  if (f.action) where.push(`action = ${next(f.action)}`);
  if (f.outcome) where.push(`outcome = ${next(f.outcome)}`);
  if (f.actor) where.push(`actor_email ILIKE ${next(like(f.actor))}`);
  if (f.document_id) where.push(`document_id = ${next(f.document_id)}`);
  if (f.from) where.push(`at >= ${next(f.from)}::date`);
  if (f.to) where.push(`at < (${next(f.to)}::date + 1)`);
  return where.length ? 'WHERE ' + where.join(' AND ') : '';
}

// ---------- CSV helpers ----------
function csvCell(v) {
  if (v === null || v === undefined) return '';
  let s = v instanceof Date ? v.toISOString() : typeof v === 'object' ? JSON.stringify(v) : String(v);
  // A cell starting with = + - @ (or a tab or return) can run as a formula when
  // the file is opened in a spreadsheet. A leading ' makes it plain text.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}
function toCsv(headers, rows) {
  return [headers.map(csvCell).join(','), ...rows.map((r) => r.map(csvCell).join(','))].join('\r\n') + '\r\n';
}
function sendCsv(res, name, csv) {
  res.set({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="${name}"`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.send('\ufeff' + csv); // the BOM makes Excel read it as UTF-8
}
const today = () => new Date().toISOString().slice(0, 10);

// ACTIVITY: the audit trail, newest first. Hashes are left out; verify has its own route.
router.get('/audit', async (req, res) => {
  const parsed = auditSchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid filters' });
  const f = parsed.data;

  const params = [];
  const whereSql = auditWhere(f, params);
  params.push(f.limit);
  const limitP = '$' + params.length;
  params.push(f.offset);
  const offsetP = '$' + params.length;

  const { rows } = await pool.query(
    `SELECT seq, at, actor_id, actor_email, action, outcome, document_id,
            target_user_id, details, ip, count(*) OVER() AS total
       FROM audit_log
       ${whereSql}
      ORDER BY seq DESC
      LIMIT ${limitP} OFFSET ${offsetP}`,
    params
  );
  res.set('X-Total-Count', String(rows[0] ? rows[0].total : 0));
  res.json(rows.map(({ total, ...row }) => row));
});

// EXPORT the activity log as CSV, with the same filters as the screen.
router.get('/audit/export', async (req, res) => {
  const parsed = auditSchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid filters' });
  const { limit, offset, ...filters } = parsed.data; // paging does not apply to an export

  const params = [];
  const whereSql = auditWhere(filters, params);
  const { rows } = await pool.query(
    `SELECT seq, at, actor_email, action, outcome, document_id, target_user_id, details, ip
       FROM audit_log ${whereSql} ORDER BY seq DESC LIMIT ${EXPORT_LIMIT}`,
    params
  );
  // Written BEFORE anything is sent. If the audit write fails, nothing is exported.
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'admin.export',
    outcome: 'allowed',
    details: { what: 'audit_log', rows: rows.length, filters },
    ip: req.ip,
  });
  sendCsv(res, `trustvault-activity-${today()}.csv`, toCsv(
    ['seq', 'time', 'actor', 'action', 'outcome', 'document_id', 'target_user_id', 'details', 'ip'],
    rows.map((r) => [r.seq, r.at, r.actor_email, r.action, r.outcome, r.document_id, r.target_user_id, r.details, r.ip])
  ));
});

// INTEGRITY: re-computes every hash in the chain.
router.get('/audit/verify', async (req, res) => {
  const result = await verifyChain();
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'admin.verify_chain',
    outcome: 'allowed',
    details: { ok: result.ok, checked: result.checked, brokenAt: result.brokenAt ?? null },
    ip: req.ip,
  });
  res.json(result);
});

// WORTH NOTICING: counts for the last 24 hours, plus two simple alarms.
router.get('/summary', async (req, res) => {
  const counts = await pool.query(
    `SELECT action, outcome, count(*)::int AS n
       FROM audit_log WHERE at > now() - interval '24 hours'
      GROUP BY action, outcome ORDER BY action, outcome`
  );
  // Someone repeatedly knocking on documents they were not given.
  const refused = await pool.query(
    `SELECT actor_email, count(*)::int AS refused, max(at) AS last_at
       FROM audit_log
      WHERE outcome = 'denied' AND action LIKE 'document.%' AND at > now() - interval '24 hours'
      GROUP BY actor_email HAVING count(*) >= 5
      ORDER BY refused DESC LIMIT 20`
  );
  // Someone guessing passwords.
  const logins = await pool.query(
    `SELECT actor_email, count(*)::int AS failures, max(at) AS last_at
       FROM audit_log
      WHERE outcome = 'denied' AND action = 'auth.login' AND at > now() - interval '24 hours'
      GROUP BY actor_email HAVING count(*) >= 5
      ORDER BY failures DESC LIMIT 20`
  );
  const chain = await verifyChain();
  res.json({
    last24h: counts.rows,
    notable: { repeated_refused_access: refused.rows, repeated_failed_logins: logins.rows },
    chain,
  });
});

// USERS. New sign-ups ('pending') come first so they are not missed.
router.get('/users', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, name, role, is_active, created_at FROM users
      ORDER BY (role = 'pending') DESC, created_at DESC LIMIT 500`
  );
  res.json(rows);
});

// EXPORT the user list as CSV. No password data is ever selected.
router.get('/users/export', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, email, role, is_active, created_at FROM users
      ORDER BY created_at DESC LIMIT ${EXPORT_LIMIT}`
  );
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'admin.export',
    outcome: 'allowed',
    details: { what: 'users', rows: rows.length },
    ip: req.ip,
  });
  sendCsv(res, `trustvault-users-${today()}.csv`, toCsv(
    ['id', 'name', 'email', 'role', 'is_active', 'created_at'],
    rows.map((u) => [u.id, u.name, u.email, u.role, u.is_active, u.created_at])
  ));
});

// Only these two fields can change. Anything else in the body is rejected.
const patchSchema = z
  .object({
    role: z.enum(['pending', 'viewer', 'owner', 'admin']).optional(),
    is_active: z.boolean().optional(),
  })
  .strict()
  .refine((v) => v.role !== undefined || v.is_active !== undefined);

router.patch('/users/:id', async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return res.status(404).json({ error: 'Not found' });
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Provide role and/or is_active only' });
  const change = parsed.data;

  // An admin can not change their own role or lock themselves out.
  // That also means the last administrator can never be removed.
  if (id === req.user.id) {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'admin.user.update',
      outcome: 'denied',
      target_user_id: id,
      details: { reason: 'self_change' },
      ip: req.ip,
    });
    return res.status(400).json({ error: 'You can not change your own account here' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const before = await client.query('SELECT id, email, role, is_active FROM users WHERE id = $1 FOR UPDATE', [id]);
    if (!before.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Not found' });
    }
    const b = before.rows[0];
    const role = change.role ?? b.role;
    const active = change.is_active ?? b.is_active;

    const upd = await client.query(
      'UPDATE users SET role = $2, is_active = $3 WHERE id = $1 RETURNING id, email, name, role, is_active',
      [id, role, active]
    );
    // Locking an account ends its sessions in the same transaction.
    if (!active) await client.query('DELETE FROM sessions WHERE user_id = $1', [id]);

    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'admin.user.update',
      outcome: 'allowed',
      target_user_id: id,
      details: { before: { role: b.role, is_active: b.is_active }, after: { role, is_active: active } },
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.json(upd.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

module.exports = router;