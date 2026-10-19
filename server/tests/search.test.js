require('dotenv').config();
const crypto = require('crypto');
const argon2 = require('argon2');
const request = require('supertest');
const app = require('../src/app');
const pool = require('../src/db');

jest.setTimeout(60000);

const tag = crypto.randomBytes(4).toString('hex');
const PASSWORD = 'TestPass#12345';
const PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n');
const users = {};
const agents = {};
let ownerDoc, strangerDoc;

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

const up = (agent, title, category) =>
  agent.post('/api/documents').field('title', title).field('category', category)
    .attach('file', PDF, { filename: 'a.pdf', contentType: 'application/pdf' });

const search = (who, query) => agents[who].get('/api/documents').query(query);
const ids = (res) => res.body.map((d) => d.id);
const today = new Date().toISOString().slice(0, 10);
const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);

beforeAll(async () => {
  await mkUser('owner', 'owner');
  await mkUser('owner', 'stranger');
  await mkUser('viewer', 'viewer');
  for (const label of Object.keys(users)) agents[label] = await login(label);

  const a = await up(agents.owner, `Salary Review ${tag}`, 'hr');
  const b = await up(agents.stranger, `Secret Strategy ${tag}`, 'finance');
  expect(a.status).toBe(201);
  expect(b.status).toBe(201);
  ownerDoc = a.body.id;
  strangerDoc = b.body.id;
});

afterAll(async () => {
  const idList = Object.values(users).map((u) => u.id);
  const docs = 'SELECT id FROM documents WHERE owner_id = ANY($1)';
  await pool.query(`DELETE FROM grants WHERE document_id IN (${docs})`, [idList]);
  await pool.query(`DELETE FROM document_blobs WHERE document_id IN (${docs})`, [idList]);
  await pool.query('DELETE FROM documents WHERE owner_id = ANY($1)', [idList]);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [idList]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [idList]);
  await pool.end();
});

describe('search filters work for the owner', () => {
  test('by name, category, owner and date', async () => {
    expect(ids(await search('owner', { q: `salary review ${tag}` }))).toEqual([ownerDoc]);
    expect(ids(await search('owner', { category: 'HR' }))).toContain(ownerDoc);
    expect(ids(await search('owner', { owner: `owner-${tag}` }))).toContain(ownerDoc);
    expect(ids(await search('owner', { from: today, to: today }))).toContain(ownerDoc);
    expect(ids(await search('owner', { from: tomorrow }))).not.toContain(ownerDoc);
  });

  test('the total count is reported', async () => {
    const res = await search('owner', { q: tag });
    expect(res.headers['x-total-count']).toBe('1');
  });
});

describe('search never leaks documents the caller can not open', () => {
  test('a stranger searching the exact title finds nothing, and the count is 0', async () => {
    const res = await search('stranger', { q: `Salary Review ${tag}` });
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    expect(res.headers['x-total-count']).toBe('0');
  });

  test('searching by the owner of a private document finds nothing', async () => {
    const res = await search('stranger', { owner: `owner-${tag}` });
    expect(ids(res)).not.toContain(ownerDoc);
    expect(res.headers['x-total-count']).toBe('0');
  });

  test('a viewer with no grants sees nothing, whatever they search', async () => {
    expect((await search('viewer', {})).body).toEqual([]);
    expect((await search('viewer', { q: tag })).body).toEqual([]);
  });

  test('wildcard characters match literally and never widen access', async () => {
    for (const q of ['%', '_', '%%', '\\']) {
      const res = await search('stranger', { q });
      expect(res.status).toBe(200);
      expect(ids(res)).not.toContain(ownerDoc);
    }
  });

  test('a document stops appearing in search once access is revoked', async () => {
    await pool.query(
      `INSERT INTO grants (document_id, user_id, level, granted_by) VALUES ($1, $2, 'read', $3)`,
      [ownerDoc, users.viewer.id, users.owner.id]
    );
    expect(ids(await search('viewer', { q: tag }))).toContain(ownerDoc);
    await pool.query('UPDATE grants SET revoked_at = now() WHERE document_id = $1 AND user_id = $2', [ownerDoc, users.viewer.id]);
    expect(ids(await search('viewer', { q: tag }))).not.toContain(ownerDoc);
  });
});

describe('bad input', () => {
  test('SQL injection text is treated as plain text', async () => {
    const res = await search('owner', { q: "'; DROP TABLE users; --", category: "x' OR '1'='1" });
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
    expect(rows[0].n).toBeGreaterThan(0);
  });

  test('invalid dates, repeated parameters and huge limits are refused', async () => {
    expect((await search('owner', { from: 'yesterday' })).status).toBe(400);
    expect((await search('owner', { from: '2026-13-45' })).status).toBe(400);
    expect((await agents.owner.get('/api/documents?q=a&q=b')).status).toBe(400);
    expect((await search('owner', { limit: 100000 })).status).toBe(400);
  });

  test('anonymous callers can not search', async () => {
    expect((await request(app).get('/api/documents').query({ q: 'a' })).status).toBe(401);
  });
});