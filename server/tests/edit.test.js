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
const PDF1 = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n');
const PDF2 = Buffer.from('%PDF-1.4\n2 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n');
const users = {};
const agents = {};
let docId;
let editorGrantId;

const binary = (res, cb) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => cb(null, Buffer.concat(chunks)));
};
const download = (agent, path) => agent.get(path).buffer(true).parse(binary);
const patch = (who, body) => agents[who].patch(`/api/documents/${docId}`).send(body);
const replace = (who, buf = PDF2, type = 'application/pdf') =>
  agents[who].post(`/api/documents/${docId}/replace`).attach('file', buf, { filename: 'new.pdf', contentType: type });
const versions = (who) => agents[who].get(`/api/documents/${docId}/versions`);
async function current() {
  const { rows } = await pool.query('SELECT title, category, owner_id, version FROM documents WHERE id = $1', [docId]);
  return rows[0];
}

async function mkUser(role, label) {
  const hash = await argon2.hash(PASSWORD);
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, role`,
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

beforeAll(async () => {
  await mkUser('owner', 'owner');
  await mkUser('viewer', 'editor');
  await mkUser('viewer', 'reader');
  await mkUser('owner', 'stranger');
  await mkUser('viewer', 'outsider');
  await mkUser('admin', 'admin');
  for (const label of Object.keys(users)) agents[label] = await login(label);

  const up = await agents.owner.post('/api/documents').field('title', 'Original title').field('category', 'hr')
    .attach('file', PDF1, { filename: 'one.pdf', contentType: 'application/pdf' });
  expect(up.status).toBe(201);
  docId = up.body.id;

  const g = await pool.query(
    `INSERT INTO grants (document_id, user_id, level, granted_by) VALUES ($1, $2, 'edit', $3) RETURNING id`,
    [docId, users.editor.id, users.owner.id]
  );
  editorGrantId = g.rows[0].id;
  await pool.query(
    `INSERT INTO grants (document_id, user_id, level, granted_by) VALUES ($1, $2, 'read', $3)`,
    [docId, users.reader.id, users.owner.id]
  );
});

afterAll(async () => {
  const ids = Object.values(users).map((u) => u.id);
  const docs = 'SELECT id FROM documents WHERE owner_id = ANY($1)';
  await pool.query(`DELETE FROM document_versions WHERE document_id IN (${docs})`, [ids]);
  await pool.query(`DELETE FROM grants WHERE document_id IN (${docs})`, [ids]);
  await pool.query(`DELETE FROM document_blobs WHERE document_id IN (${docs})`, [ids]);
  await pool.query('DELETE FROM documents WHERE owner_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [ids]);
  await pool.end();
});

describe('who may edit', () => {
  test('anonymous callers get 401', async () => {
    expect((await request(app).patch(`/api/documents/${docId}`).send({ title: 'x' })).status).toBe(401);
    expect((await request(app).post(`/api/documents/${docId}/replace`)).status).toBe(401);
  });

  test.each(['reader', 'stranger', 'outsider', 'admin'])('%s can not change or replace anything', async (who) => {
    expect((await patch(who, { title: 'Hacked' })).status).toBe(404);
    expect((await replace(who)).status).toBe(404);
    const doc = await current();
    expect(doc.title).toBe('Original title');
    expect(doc.version).toBe(1);
  });

  test('the refusals are audited', async () => {
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_log WHERE action = 'document.edit' AND outcome = 'denied' AND actor_id = $1 AND document_id = $2`,
      [users.reader.id, docId]
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });
});

describe('an editor', () => {
  test('can change the title and category, and only those', async () => {
    const res = await patch('editor', { title: 'Renamed', category: 'finance' });
    expect(res.status).toBe(200);
    const doc = await current();
    expect(doc.title).toBe('Renamed');
    expect(doc.category).toBe('finance');
    expect(doc.owner_id).toBe(users.owner.id);
  });

  test('bad input is refused, and extra fields are never accepted', async () => {
    expect((await patch('editor', {})).status).toBe(400);
    expect((await patch('editor', { title: '' })).status).toBe(400);
    expect((await patch('editor', { title: 'x'.repeat(201) })).status).toBe(400);
    expect((await patch('editor', { title: 'Mine now', owner_id: users.editor.id })).status).toBe(400);
    const doc = await current();
    expect(doc.owner_id).toBe(users.owner.id);
    expect(doc.title).toBe('Renamed');
  });

  test('the audit says which fields changed, but never the titles', async () => {
    const { rows } = await pool.query(
      `SELECT details FROM audit_log WHERE action = 'document.edit' AND outcome = 'allowed' AND document_id = $1`,
      [docId]
    );
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const text = JSON.stringify(rows);
    expect(text).toContain('"fields"');
    expect(text).not.toContain('Renamed');
    expect(text).not.toContain('Original title');
  });

  test('can replace the file, and readers then get the new one', async () => {
    const res = await replace('editor');
    expect(res.status).toBe(200);
    expect(res.body.version).toBe(2);
    const dl = await download(agents.reader, `/api/documents/${docId}/download`);
    expect(dl.status).toBe(200);
    expect(dl.body.equals(PDF2)).toBe(true);
  });

  test('a file that is not really a PDF is refused, and nothing changes', async () => {
    const res = await replace('editor', Buffer.from('just some text, not a pdf'), 'application/pdf');
    expect(res.status).toBe(400);
    expect((await current()).version).toBe(2);
  });

  test('still can not delete, share, or see the version history', async () => {
    expect((await agents.editor.delete(`/api/documents/${docId}`)).status).toBe(404);
    const share = await agents.editor.post(`/api/documents/${docId}/grants`).send({ email: users.outsider.email, level: 'read' });
    expect(share.status).toBe(404);
    expect((await versions('editor')).status).toBe(404);
    expect((await versions('reader')).status).toBe(404);
    expect((await versions('admin')).status).toBe(404);
  });
});

describe('earlier versions', () => {
  test('the owner can list them and get the original file back', async () => {
    const list = await versions('owner');
    expect(list.status).toBe(200);
    expect(list.body).toHaveLength(1);
    expect(list.body[0].version).toBe(1);
    const dl = await download(agents.owner, `/api/documents/${docId}/versions/1/download`);
    expect(dl.status).toBe(200);
    expect(dl.body.equals(PDF1)).toBe(true);
  });

  test('nobody else can download an earlier version', async () => {
    for (const who of ['editor', 'reader', 'stranger', 'admin']) {
      expect((await download(agents[who], `/api/documents/${docId}/versions/1/download`)).status).toBe(404);
    }
    expect((await download(agents.owner, `/api/documents/${docId}/versions/abc/download`)).status).toBe(404);
    expect((await download(agents.owner, `/api/documents/${docId}/versions/99/download`)).status).toBe(404);
  });

  test('there is a limit on how many are kept', async () => {
    for (let v = 100; v < 119; v++) {
      await pool.query(
        `INSERT INTO document_versions (document_id, version, original_filename, mime_type, size_bytes, sha256, data, replaced_by)
         VALUES ($1, $2, 'old.pdf', 'application/pdf', 1, 'x', $3, $4)`,
        [docId, v, Buffer.from('x'), users.editor.id]
      );
    }
    expect((await replace('editor')).status).toBe(409);
    expect((await current()).version).toBe(2);
  });
});

describe('taking edit access away', () => {
  test('works on the very next request', async () => {
    await pool.query('UPDATE grants SET revoked_at = now() WHERE id = $1', [editorGrantId]);
    expect((await patch('editor', { title: 'Again' })).status).toBe(404);
    expect((await replace('editor')).status).toBe(404);
    expect((await current()).title).toBe('Renamed');
  });

  test('a deleted document can not be edited, even by its owner, and the chain is intact', async () => {
    expect((await agents.owner.delete(`/api/documents/${docId}`)).status).toBe(200);
    expect((await patch('owner', { title: 'Late' })).status).toBe(404);
    expect((await verifyChain()).ok).toBe(true);
  });
});