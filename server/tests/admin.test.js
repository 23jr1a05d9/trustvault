require('dotenv').config();
const crypto = require('crypto');
const argon2 = require('argon2');
const request = require('supertest');
const app = require('../src/app');
const pool = require('../src/db');

jest.setTimeout(60000);

const tag = crypto.randomBytes(4).toString('hex');
const PASSWORD = 'TestPass#12345';
const users = {};
const agents = {};

async function mkUser(role, label) {
  const hash = await argon2.hash(PASSWORD);
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, role`,
    [`${label}-${tag}@test.local`, `${label}-${tag}`, hash, role]
  );
  users[label] = rows[0];
}

async function login(label) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ email: users[label].email, password: PASSWORD });
  expect(res.status).toBe(200);
  return agent;
}

const patch = (who, id, body) => agents[who].patch(`/api/admin/users/${id}`).send(body);

beforeAll(async () => {
  await mkUser('admin', 'admin');
  await mkUser('owner', 'owner');
  await mkUser('viewer', 'viewer');
  await mkUser('viewer', 'victim');
  await mkUser('viewer', 'promotee');
  for (const label of Object.keys(users)) agents[label] = await login(label);
});

afterAll(async () => {
  const ids = Object.values(users).map((u) => u.id);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [ids]);
  await pool.end();
});

const ADMIN_PATHS = ['/api/admin/audit', '/api/admin/audit/verify', '/api/admin/summary', '/api/admin/users'];

describe('who may call the admin endpoints', () => {
  test.each(ADMIN_PATHS)('anonymous callers get 401 on %s', async (path) => {
    expect((await request(app).get(path)).status).toBe(401);
  });

  test.each(['owner', 'viewer'])('%s gets 403 on every admin endpoint', async (who) => {
    for (const path of ADMIN_PATHS) {
      expect((await agents[who].get(path)).status).toBe(403);
    }
    expect((await patch(who, users.victim.id, { role: 'admin' })).status).toBe(403);
    const { rows } = await pool.query('SELECT role FROM users WHERE id = $1', [users.victim.id]);
    expect(rows[0].role).toBe('viewer');
  });

  test('anonymous callers can not change users', async () => {
    const res = await request(app).patch(`/api/admin/users/${users.victim.id}`).send({ role: 'admin' });
    expect(res.status).toBe(401);
  });

  test('a refused admin attempt is recorded, and the admin can see it', async () => {
    const res = await agents.admin.get('/api/admin/audit').query({ action: 'admin.access', outcome: 'denied', actor: `viewer-${tag}` });
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect(res.body[0].actor_email).toBe(users.viewer.email);
  });
});

describe('what the admin sees', () => {
  test('the audit trail, filtered by group', async () => {
    const res = await agents.admin.get('/api/admin/audit').query({ group: 'auth', limit: 10 });
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);
    for (const row of res.body) expect(row.action.startsWith('auth.')).toBe(true);
    expect(Number(res.headers['x-total-count'])).toBeGreaterThanOrEqual(res.body.length);
    expect(res.body[0]).not.toHaveProperty('row_hash');
  });

  test('bad filters are refused', async () => {
    expect((await agents.admin.get('/api/admin/audit').query({ group: 'everything' })).status).toBe(400);
    expect((await agents.admin.get('/api/admin/audit').query({ document_id: 'nope' })).status).toBe(400);
    expect((await agents.admin.get('/api/admin/audit').query({ limit: 100000 })).status).toBe(400);
    expect((await agents.admin.get('/api/admin/audit?actor=a&actor=b')).status).toBe(400);
  });

  test('SQL text in a filter is treated as plain text', async () => {
    const res = await agents.admin.get('/api/admin/audit').query({ actor: "'; DROP TABLE users; --" });
    expect(res.status).toBe(200);
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
    expect(rows[0].n).toBeGreaterThan(0);
  });

  test('the chain verifies', async () => {
    const res = await agents.admin.get('/api/admin/audit/verify');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('repeated failed logins show up as worth noticing', async () => {
    for (let i = 0; i < 5; i++) {
      await request(app).post('/api/auth/login').send({ email: users.viewer.email, password: 'wrong-password-' + i });
    }
    const res = await agents.admin.get('/api/admin/summary');
    expect(res.status).toBe(200);
    const emails = res.body.notable.repeated_failed_logins.map((r) => r.actor_email);
    expect(emails).toContain(users.viewer.email);
    expect(res.body.chain.ok).toBe(true);
  });

  test('the user list never exposes password hashes', async () => {
    const res = await agents.admin.get('/api/admin/users');
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toMatch(/password|argon2/i);
  });
});

describe('managing users', () => {
  test('locking an account ends its session at once, and it is audited', async () => {
    expect((await agents.victim.get('/api/auth/me')).status).toBe(200);
    const res = await patch('admin', users.victim.id, { is_active: false });
    expect(res.status).toBe(200);
    expect(res.body.is_active).toBe(false);
    expect((await agents.victim.get('/api/auth/me')).status).toBe(401);

    const login = await request(app).post('/api/auth/login').send({ email: users.victim.email, password: PASSWORD });
    expect(login.status).toBe(401);

    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log
        WHERE action = 'admin.user.update' AND outcome = 'allowed' AND target_user_id = $1 AND actor_id = $2`,
      [users.victim.id, users.admin.id]
    );
    expect(rows[0].n).toBe(1);
  });

  test('unlocking lets the person log in again', async () => {
    expect((await patch('admin', users.victim.id, { is_active: true })).status).toBe(200);
    const login = await request(app).post('/api/auth/login').send({ email: users.victim.email, password: PASSWORD });
    expect(login.status).toBe(200);
  });

  test('a role change takes effect on the very next request', async () => {
    expect((await agents.promotee.get('/api/auth/me')).body.role).toBe('viewer');
    expect((await patch('admin', users.promotee.id, { role: 'owner' })).status).toBe(200);
    expect((await agents.promotee.get('/api/auth/me')).body.role).toBe('owner');
  });

  test('an admin can not change their own account', async () => {
    expect((await patch('admin', users.admin.id, { role: 'viewer' })).status).toBe(400);
    expect((await patch('admin', users.admin.id, { is_active: false })).status).toBe(400);
    expect((await agents.admin.get('/api/auth/me')).body.role).toBe('admin');
  });

  test('bad input is refused', async () => {
    expect((await patch('admin', users.victim.id, { role: 'superadmin' })).status).toBe(400);
    expect((await patch('admin', users.victim.id, { password_hash: 'x' })).status).toBe(400);
    expect((await patch('admin', users.victim.id, {})).status).toBe(400);
    expect((await patch('admin', 'not-a-uuid', { role: 'viewer' })).status).toBe(404);
    expect((await patch('admin', crypto.randomUUID(), { role: 'viewer' })).status).toBe(404);
  });
});