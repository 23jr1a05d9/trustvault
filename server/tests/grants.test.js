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
const PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n');
const users = {};
const agents = {};
let docId, otherDocId, otherGrantId;

const binary = (res, cb) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => cb(null, Buffer.concat(chunks)));
};
const download = (agent, id) => agent.get(`/api/documents/${id}/download`).buffer(true).parse(binary);
const share = (agent, id, body) => agent.post(`/api/documents/${id}/grants`).send(body);
const email = (label) => users[label].email;

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

const uploadPdf = (agent) =>
  agent.post('/api/documents').field('title', 'T')
    .attach('file', PDF, { filename: 'a.pdf', contentType: 'application/pdf' });

async function countGrants(documentId, userId) {
  const { rows } = await pool.query(
    'SELECT count(*)::int AS n FROM grants WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL',
    [documentId, userId]
  );
  return rows[0].n;
}

async function countAudit(action, outcome, extra = '', params = []) {
  const { rows } = await pool.query(
    `SELECT count(*)::int AS n FROM audit_log WHERE action = $1 AND outcome = $2 ${extra}`,
    [action, outcome, ...params]
  );
  return rows[0].n;
}

beforeAll(async () => {
  await mkUser('owner', 'owner');
  await mkUser('owner', 'stranger'); // another owner
  await mkUser('viewer', 'viewer');
  await mkUser('viewer', 'editor');
  await mkUser('viewer', 'outsider');
  for (const label of Object.keys(users)) agents[label] = await login(label);

  const a = await uploadPdf(agents.owner);
  expect(a.status).toBe(201);
  docId = a.body.id;

  // The stranger has their own document, shared with the outsider.
  const b = await uploadPdf(agents.stranger);
  expect(b.status).toBe(201);
  otherDocId = b.body.id;
  const g = await share(agents.stranger, otherDocId, { email: email('outsider'), level: 'read' });
  expect(g.status).toBe(201);
  otherGrantId = g.body.id;
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

describe('before any grant', () => {
  test('the viewer can not download', async () => {
    expect((await download(agents.viewer, docId)).status).toBe(404);
  });
});

describe('only the owner can change who has access', () => {
  test.each(['viewer', 'outsider', 'stranger'])('%s can not grant access to the document', async (who) => {
    const res = await share(agents[who], docId, { email: email(who), level: 'edit' });
    expect(res.status).toBe(404);
    expect(await countGrants(docId, users[who].id)).toBe(0);
  });

  test('anonymous callers are refused with 401', async () => {
    expect((await request(app).post(`/api/documents/${docId}/grants`).send({})).status).toBe(401);
    expect((await request(app).get(`/api/documents/${docId}/grants`)).status).toBe(401);
    expect((await request(app).delete(`/api/documents/${docId}/grants/${otherGrantId}`)).status).toBe(401);
  });

  test('non-owners can not list who has access', async () => {
    for (const who of ['viewer', 'outsider', 'stranger']) {
      expect((await agents[who].get(`/api/documents/${docId}/grants`)).status).toBe(404);
    }
  });
});

describe('validation', () => {
  test.each(['admin', 'owner', 'delete', ''])('level "%s" is rejected', async (level) => {
    expect((await share(agents.owner, docId, { email: email('viewer'), level })).status).toBe(400);
  });

  test('unknown email, self grant and past expiry are rejected', async () => {
    expect((await share(agents.owner, docId, { email: 'nobody@test.local', level: 'read' })).status).toBe(400);
    expect((await share(agents.owner, docId, { email: email('owner'), level: 'read' })).status).toBe(400);
    const past = new Date(Date.now() - 3600 * 1000).toISOString();
    expect((await share(agents.owner, docId, { email: email('viewer'), level: 'read', expires_at: past })).status).toBe(400);
  });

  test('a malformed document id is a 404', async () => {
    expect((await share(agents.owner, 'not-a-uuid', { email: email('viewer'), level: 'read' })).status).toBe(404);
  });
});

describe('granting', () => {
  test('the owner grants read, and the viewer can then download', async () => {
    const res = await share(agents.owner, docId, { email: email('viewer'), level: 'read' });
    expect(res.status).toBe(201);
    expect(res.body.level).toBe('read');
    const dl = await download(agents.viewer, docId);
    expect(dl.status).toBe(200);
    expect(dl.body.equals(PDF)).toBe(true);
  });

  test('a read grant can not delete, list grants or share', async () => {
    expect((await agents.viewer.delete(`/api/documents/${docId}`)).status).toBe(404);
    expect((await agents.viewer.get(`/api/documents/${docId}/grants`)).status).toBe(404);
    expect((await share(agents.viewer, docId, { email: email('outsider'), level: 'read' })).status).toBe(404);
    expect((await download(agents.outsider, docId)).status).toBe(404);
  });

  test('an edit grant still can not re-share the document', async () => {
    expect((await share(agents.owner, docId, { email: email('editor'), level: 'edit' })).status).toBe(201);
    expect((await share(agents.editor, docId, { email: email('outsider'), level: 'read' })).status).toBe(404);
    expect((await download(agents.outsider, docId)).status).toBe(404);
  });

  test('changing a level keeps one active grant and keeps the history', async () => {
    const res = await share(agents.owner, docId, { email: email('viewer'), level: 'edit' });
    expect(res.status).toBe(201);
    expect(await countGrants(docId, users.viewer.id)).toBe(1);
    const { rows } = await pool.query(
      'SELECT count(*)::int AS n FROM grants WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NOT NULL',
      [docId, users.viewer.id]
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });

  test('the owner can list who has access', async () => {
    const res = await agents.owner.get(`/api/documents/${docId}/grants`);
    expect(res.status).toBe(200);
    expect(res.body.map((g) => g.email).sort()).toEqual([email('editor'), email('viewer')].sort());
  });
});

describe('revoking', () => {
  test('an owner can not revoke a grant that belongs to another document', async () => {
    const res = await agents.owner.delete(`/api/documents/${docId}/grants/${otherGrantId}`);
    expect(res.status).toBe(404);
    const { rows } = await pool.query('SELECT revoked_at FROM grants WHERE id = $1', [otherGrantId]);
    expect(rows[0].revoked_at).toBeNull();
    expect((await download(agents.outsider, otherDocId)).status).toBe(200);
  });

  test('another owner can not revoke grants on this document', async () => {
    const list = await agents.owner.get(`/api/documents/${docId}/grants`);
    const viewerGrant = list.body.find((g) => g.email === email('viewer'));
    expect((await agents.stranger.delete(`/api/documents/${docId}/grants/${viewerGrant.id}`)).status).toBe(404);
    expect((await download(agents.viewer, docId)).status).toBe(200);
  });

  test('revoking works on the very next request, and can not be repeated', async () => {
    const list = await agents.owner.get(`/api/documents/${docId}/grants`);
    const viewerGrant = list.body.find((g) => g.email === email('viewer'));
    expect((await download(agents.viewer, docId)).status).toBe(200);

    expect((await agents.owner.delete(`/api/documents/${docId}/grants/${viewerGrant.id}`)).status).toBe(200);

    expect((await download(agents.viewer, docId)).status).toBe(404);
    expect((await agents.viewer.get(`/api/documents/${docId}`)).status).toBe(404);
    const mine = await agents.viewer.get('/api/documents');
    expect(mine.body.map((d) => d.id)).not.toContain(docId);
    expect((await agents.owner.delete(`/api/documents/${docId}/grants/${viewerGrant.id}`)).status).toBe(404);
  });

  test('a grant stops working when it expires', async () => {
    const future = new Date(Date.now() + 3600 * 1000).toISOString();
    const res = await share(agents.owner, docId, { email: email('outsider'), level: 'read', expires_at: future });
    expect(res.status).toBe(201);
    expect((await download(agents.outsider, docId)).status).toBe(200);
    await pool.query("UPDATE grants SET expires_at = now() - interval '1 minute' WHERE id = $1", [res.body.id]);
    expect((await download(agents.outsider, docId)).status).toBe(404);
  });

  test('a deactivated user is locked out at once, session and all', async () => {
    expect((await agents.editor.get('/api/auth/me')).status).toBe(200);
    expect((await download(agents.editor, docId)).status).toBe(200);
    await pool.query('UPDATE users SET is_active = false WHERE id = $1', [users.editor.id]);
    expect((await agents.editor.get('/api/auth/me')).status).toBe(401);
    expect((await download(agents.editor, docId)).status).toBe(401);
  });
});

describe('audit trail', () => {
  test('grants and revocations are recorded', async () => {
    const withDoc = 'AND document_id = $3';
    expect(await countAudit('permission.grant', 'allowed', withDoc, [docId])).toBeGreaterThanOrEqual(4);
    expect(await countAudit('permission.revoke', 'allowed', withDoc, [docId])).toBeGreaterThanOrEqual(1);
  });

  test('refused attempts are recorded, with who tried', async () => {
    const n = await countAudit('document.share', 'denied', 'AND actor_id = $3 AND document_id = $4', [users.stranger.id, docId]);
    expect(n).toBeGreaterThanOrEqual(1);
    const m = await countAudit('permission.grant', 'denied', 'AND actor_id = $3 AND document_id = $4', [users.owner.id, docId]);
    expect(m).toBeGreaterThanOrEqual(1);
  });

  test('the audit chain is still intact', async () => {
    const result = await verifyChain();
    expect(result.ok).toBe(true);
  });
});