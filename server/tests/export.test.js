require('dotenv').config();
const crypto = require('crypto');
const argon2 = require('argon2');
const request = require('supertest');
const app = require('../src/app');
const pool = require('../src/db');
const { verifyChain } = require('../src/audit');

jest.setTimeout(60000);

const tag = crypto.randomBytes(4).toString('hex');
const PASSWORD = 'TestPass#12345';
const AUDIT = '/api/admin/audit/export';
const USERS = '/api/admin/users/export';
const users = {};
const agents = {};

async function mkUser(role, label, name = label) {
  const hash = await argon2.hash(PASSWORD);
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, role`,
    [`${label}-${tag}@test.local`, name, hash, role]
  );
  users[label] = rows[0];
}

async function login(label) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ email: users[label].email, password: PASSWORD });
  expect(res.status).toBe(200);
  return agent;
}

beforeAll(async () => {
  await mkUser('admin', 'admin');
  await mkUser('owner', 'owner');
  await mkUser('viewer', 'viewer');
  await mkUser('viewer', 'evil', '=HYPERLINK("http://evil.example","click")');
  for (const label of ['admin', 'owner', 'viewer']) agents[label] = await login(label);
});

afterAll(async () => {
  const ids = Object.values(users).map((u) => u.id);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [ids]);
  await pool.end();
});

describe('who may export', () => {
  test.each([AUDIT, USERS])('anonymous callers get 401 on %s', async (path) => {
    expect((await request(app).get(path)).status).toBe(401);
  });

  test.each([AUDIT, USERS])('owners and viewers get 403 on %s', async (path) => {
    expect((await agents.owner.get(path)).status).toBe(403);
    expect((await agents.viewer.get(path)).status).toBe(403);
  });
});

describe('the activity export', () => {
  test('is a safe CSV download without hash data', async () => {
    const res = await agents.admin.get(AUDIT);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.text.startsWith('\ufeff"seq","time","actor"')).toBe(true);
    expect(res.text).not.toMatch(/argon2|row_hash|prev_hash/i);
  });

  test('respects the filters', async () => {
    const res = await agents.admin.get(AUDIT).query({ outcome: 'denied', actor: `viewer-${tag}` });
    expect(res.status).toBe(200);
    const lines = res.text.trim().split('\r\n').slice(1);
    expect(lines.length).toBeGreaterThanOrEqual(1);
    for (const line of lines) {
      expect(line).toContain('"denied"');
      expect(line).toContain(users.viewer.email);
    }
  });

  test('bad filters are refused', async () => {
    expect((await agents.admin.get(AUDIT).query({ group: 'everything' })).status).toBe(400);
    expect((await agents.admin.get(AUDIT).query({ document_id: 'nope' })).status).toBe(400);
    expect((await agents.admin.get(AUDIT + '?actor=a&actor=b')).status).toBe(400);
  });

  test('a refused export attempt and a real export are both audited', async () => {
    const denied = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log WHERE action = 'admin.access' AND outcome = 'denied' AND actor_id = $1`,
      [users.viewer.id]
    );
    expect(denied.rows[0].n).toBeGreaterThanOrEqual(1);
    const done = await pool.query(
      `SELECT details FROM audit_log WHERE action = 'admin.export' AND outcome = 'allowed' AND actor_id = $1`,
      [users.admin.id]
    );
    expect(done.rows.some((r) => r.details.what === 'audit_log')).toBe(true);
  });
});

describe('the user export', () => {
  test('lists people without any password data', async () => {
    const res = await agents.admin.get(USERS);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/csv/);
    expect(res.text.startsWith('\ufeff"id","name","email","role","is_active","created_at"')).toBe(true);
    expect(res.text).toContain(users.owner.email);
    expect(res.text).not.toMatch(/password|argon2|hash/i);
  });

  test('spreadsheet formulas in names are defused', async () => {
    const res = await agents.admin.get(USERS);
    expect(res.text).toContain('"\'=HYPERLINK(');
    expect(res.text).not.toContain('"=HYPERLINK(');
  });

  test('the export is audited, and the chain is intact', async () => {
    const { rows } = await pool.query(
      `SELECT details FROM audit_log WHERE action = 'admin.export' AND outcome = 'allowed' AND actor_id = $1`,
      [users.admin.id]
    );
    expect(rows.some((r) => r.details.what === 'users')).toBe(true);
    expect((await verifyChain()).ok).toBe(true);
  });
});