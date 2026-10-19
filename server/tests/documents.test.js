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

const binary = (res, cb) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => cb(null, Buffer.concat(chunks)));
};
const download = (agent, id) => agent.get(`/api/documents/${id}/download`).buffer(true).parse(binary);

async function mkUser(role, label) {
  const hash = await argon2.hash(PASSWORD);
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role)
     VALUES ($1, $2, $3, $4) RETURNING id, email, role`,
    [`${label}-${tag}@test.local`, label, hash, role]
  );
  users[label] = rows[0];
}

async function login(label) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ email: users[label].email, password: PASSWORD });
  expect(res.status).toBe(200);
  return agent;
}

function send(agent, buffer, filename, type, fields = { title: 'T' }) {
  let r = agent.post('/api/documents');
  for (const [k, v] of Object.entries(fields)) r = r.field(k, v);
  return r.attach('file', buffer, { filename, contentType: type });
}

beforeAll(async () => {
  await mkUser('owner', 'owner');
  await mkUser('owner', 'stranger'); // a second owner with no grant
  await mkUser('viewer', 'viewer'); // will be granted read
  await mkUser('viewer', 'outsider'); // never granted anything
  await mkUser('admin', 'admin');
  for (const label of Object.keys(users)) agents[label] = await login(label);

  const up = await send(agents.owner, PDF, 'letter.pdf', 'application/pdf', { title: 'Salary letter', category: 'hr' });
  expect(up.status).toBe(201);
  docId = up.body.id;
  await pool.query(
    `INSERT INTO grants (document_id, user_id, level, granted_by) VALUES ($1, $2, 'read', $3)`,
    [docId, users.viewer.id, users.owner.id]
  );
});

afterAll(async () => {
  const ids = Object.values(users).map((u) => u.id);
  await pool.query('DELETE FROM grants WHERE document_id IN (SELECT id FROM documents WHERE owner_id = ANY($1))', [ids]);
  await pool.query('DELETE FROM document_blobs WHERE document_id IN (SELECT id FROM documents WHERE owner_id = ANY($1))', [ids]);
  await pool.query('DELETE FROM documents WHERE owner_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [ids]);
  await pool.end();
});

describe('anonymous callers', () => {
  test.each([
    ['list', 'get', () => '/api/documents'],
    ['details', 'get', () => `/api/documents/${docId}`],
    ['download', 'get', () => `/api/documents/${docId}/download`],
    ['delete', 'delete', () => `/api/documents/${docId}`],
    ['upload', 'post', () => '/api/documents'],
  ])('%s is refused with 401', async (_label, method, path) => {
    const res = await request(app)[method](path());
    expect(res.status).toBe(401);
  });
});

describe('users who were never granted access', () => {
  test.each(['stranger', 'outsider', 'admin'])('%s gets 404 on details, download and delete', async (who) => {
    expect((await agents[who].get(`/api/documents/${docId}`)).status).toBe(404);
    expect((await download(agents[who], docId)).status).toBe(404);
    expect((await agents[who].delete(`/api/documents/${docId}`)).status).toBe(404);
  });

  test.each(['stranger', 'outsider', 'admin'])('%s does not see the document in their list', async (who) => {
    const res = await agents[who].get('/api/documents');
    expect(res.status).toBe(200);
    expect(res.body.map((d) => d.id)).not.toContain(docId);
  });

  test('the document is untouched after those attempts', async () => {
    const res = await download(agents.owner, docId);
    expect(res.status).toBe(200);
    expect(res.body.equals(PDF)).toBe(true);
  });

  test.each(['stranger', 'outsider', 'admin'])('refused attempts by %s are in the audit log', async (who) => {
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log
        WHERE actor_id = $1 AND action = 'document.download' AND outcome = 'denied' AND document_id = $2`,
      [users[who].id, docId]
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });
});

describe('a viewer with a read grant', () => {
  test('sees the document and downloads it with safe headers', async () => {
    const list = await agents.viewer.get('/api/documents');
    expect(list.body.map((d) => d.id)).toContain(docId);

    const res = await download(agents.viewer, docId);
    expect(res.status).toBe(200);
    expect(res.body.equals(PDF)).toBe(true);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-type']).toMatch(/application\/pdf/);
  });

  test('can not delete it', async () => {
    expect((await agents.viewer.delete(`/api/documents/${docId}`)).status).toBe(404);
  });

  test('the successful download is audited', async () => {
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log
        WHERE actor_id = $1 AND action = 'document.download' AND outcome = 'allowed' AND document_id = $2`,
      [users.viewer.id, docId]
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });

  test('loses access on the very next request after the grant is revoked', async () => {
    await pool.query('UPDATE grants SET revoked_at = now() WHERE document_id = $1 AND user_id = $2', [docId, users.viewer.id]);
    expect((await download(agents.viewer, docId)).status).toBe(404);
    expect((await agents.viewer.get(`/api/documents/${docId}`)).status).toBe(404);
  });
});

describe('upload checks', () => {
  test('a viewer can not upload (403)', async () => {
    const res = await send(agents.viewer, PDF, 'x.pdf', 'application/pdf');
    expect(res.status).toBe(403);
  });

  test('text pretending to be a PDF is rejected', async () => {
    const res = await send(agents.owner, Buffer.from('just some text, not a pdf'), 'evil.pdf', 'application/pdf');
    expect(res.status).toBe(400);
  });

  test('HTML pretending to be a PNG is rejected', async () => {
    const res = await send(agents.owner, Buffer.from('<html><script>alert(1)</script></html>'), 'x.png', 'image/png');
    expect(res.status).toBe(400);
  });

  test('files over 10 MB are rejected', async () => {
    const res = await send(agents.owner, Buffer.alloc(10 * 1024 * 1024 + 1, 'a'), 'big.pdf', 'application/pdf');
    expect(res.status).toBe(413);
  });

  test('owner_id and role in the form are ignored', async () => {
    const res = await send(agents.owner, PDF, 'b.pdf', 'application/pdf', {
      title: 'Mass assignment',
      owner_id: users.viewer.id,
      role: 'admin',
    });
    expect(res.status).toBe(201);
    const { rows } = await pool.query('SELECT owner_id FROM documents WHERE id = $1', [res.body.id]);
    expect(rows[0].owner_id).toBe(users.owner.id);
  });

  test('a good upload is audited', async () => {
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log
        WHERE action = 'document.upload' AND outcome = 'allowed' AND document_id = $1`,
      [docId]
    );
    expect(rows[0].n).toBe(1);
  });
});

describe('deleting', () => {
  test('the owner can delete, and then nobody can download it', async () => {
    expect((await agents.owner.delete(`/api/documents/${docId}`)).status).toBe(200);
    expect((await download(agents.owner, docId)).status).toBe(404);
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log
        WHERE action = 'document.delete' AND outcome = 'allowed' AND document_id = $1`,
      [docId]
    );
    expect(rows[0].n).toBe(1);
  });
});