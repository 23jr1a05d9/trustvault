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
let docId;

async function mkUser(role, label, active = true) {
  const hash = await argon2.hash(PASSWORD);
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role, is_active) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, role`,
    [`${label}-${tag}@test.local`, `${label}-${tag}`, hash, role, active]
  );
  users[label] = rows[0];
}

async function login(label) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ email: users[label].email, password: PASSWORD });
  expect(res.status).toBe(200);
  return agent;
}

const shareWith = (who) =>
  agents.owner.post(`/api/documents/${docId}/grants`).send({ email: users[who].email, level: 'read' });

beforeAll(async () => {
  await mkUser('owner', 'owner');
  await mkUser('owner', 'owner2');
  await mkUser('viewer', 'viewer');
  await mkUser('viewer', 'viewer2');
  await mkUser('pending', 'pending');
  await mkUser('admin', 'admin');
  await mkUser('viewer', 'locked', false);
  for (const label of ['owner', 'owner2', 'viewer', 'viewer2', 'pending', 'admin']) agents[label] = await login(label);

  const up = await agents.owner.post('/api/documents').field('title', 'T').field('category', 'hr')
    .attach('file', PDF, { filename: 'a.pdf', contentType: 'application/pdf' });
  expect(up.status).toBe(201);
  docId = up.body.id;
});

afterAll(async () => {
  const ids = Object.values(users).map((u) => u.id);
  const docs = 'SELECT id FROM documents WHERE owner_id = ANY($1)';
  await pool.query(`DELETE FROM grants WHERE document_id IN (${docs})`, [ids]);
  await pool.query(`DELETE FROM document_blobs WHERE document_id IN (${docs})`, [ids]);
  await pool.query('DELETE FROM documents WHERE owner_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [ids]);
  await pool.end();
});

describe('who may look people up', () => {
  test('anonymous callers get 401', async () => {
    expect((await request(app).get('/api/directory')).status).toBe(401);
  });

  test.each(['viewer', 'admin', 'pending'])('%s gets 403', async (who) => {
    expect((await agents[who].get('/api/directory')).status).toBe(403);
  });

  test('a refused lookup is audited', async () => {
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log WHERE action = 'directory.list' AND outcome = 'denied' AND actor_id = $1`,
      [users.viewer.id]
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });
});

describe('what an owner sees', () => {
  test('approved viewers and owners, but never themselves, admins, pending or locked accounts', async () => {
    const res = await agents.owner.get('/api/directory');
    expect(res.status).toBe(200);
    const emails = res.body.map((p) => p.email);
    expect(emails).toContain(users.viewer.email);
    expect(emails).toContain(users.owner2.email);
    for (const who of ['owner', 'admin', 'pending', 'locked']) expect(emails).not.toContain(users[who].email);
  });

  test('no password data is returned', async () => {
    const res = await agents.owner.get('/api/directory');
    expect(JSON.stringify(res.body)).not.toMatch(/password|argon2|hash/i);
  });
});

describe('sharing is limited to approved people', () => {
  test.each(['pending', 'admin', 'locked'])('an owner can not share with a %s account', async (who) => {
    expect((await shareWith(who)).status).toBe(400);
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM grants WHERE document_id = $1 AND user_id = $2', [docId, users[who].id]);
    expect(rows[0].n).toBe(0);
  });

  test('an owner can share with several approved people in a row', async () => {
    for (const who of ['viewer', 'viewer2', 'owner2']) expect((await shareWith(who)).status).toBe(201);
    for (const who of ['viewer', 'viewer2', 'owner2']) {
      expect((await agents[who].get(`/api/documents/${docId}`)).status).toBe(200);
    }
    expect((await agents.pending.get(`/api/documents/${docId}`)).status).toBe(404);
  });
});