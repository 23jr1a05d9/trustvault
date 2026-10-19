require('dotenv').config();
const crypto = require('crypto');
const pool = require('../src/db');
const { authorize } = require('../src/authorize');

jest.setTimeout(30000);

const tag = crypto.randomBytes(4).toString('hex');
let owner, stranger, reader, editor, revoked, expired, admin, doc;

async function mkUser(role, label) {
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role)
     VALUES ($1, $2, 'x', $3) RETURNING id, email, name, role`,
    [`${label}-${tag}@test.local`, label, role]
  );
  return rows[0];
}

async function mkGrant(userId, level, { expires = null, revokedNow = false } = {}) {
  await pool.query(
    `INSERT INTO grants (document_id, user_id, level, granted_by, expires_at, revoked_at)
     VALUES ($1, $2, $3, $4, $5, ${revokedNow ? 'now()' : 'NULL'})`,
    [doc.id, userId, level, owner.id, expires]
  );
}

beforeAll(async () => {
  owner = await mkUser('owner', 'owner');
  stranger = await mkUser('owner', 'stranger'); // another owner, no grant
  reader = await mkUser('viewer', 'reader');
  editor = await mkUser('viewer', 'editor');
  revoked = await mkUser('viewer', 'revoked');
  expired = await mkUser('viewer', 'expired');
  admin = await mkUser('admin', 'admin');

  const { rows } = await pool.query(
    `INSERT INTO documents (owner_id, title, original_filename, mime_type, size_bytes, storage_key, sha256)
     VALUES ($1, 'Test doc', 'a.pdf', 'application/pdf', 1, $2, 'x') RETURNING *`,
    [owner.id, 'test-' + tag]
  );
  doc = rows[0];

  await mkGrant(reader.id, 'read');
  await mkGrant(editor.id, 'edit');
  await mkGrant(revoked.id, 'read', { revokedNow: true });
  await mkGrant(expired.id, 'read', { expires: new Date(Date.now() - 3600 * 1000) });
});

afterAll(async () => {
  await pool.query('DELETE FROM grants WHERE document_id = $1', [doc.id]);
  await pool.query('DELETE FROM documents WHERE id = $1', [doc.id]);
  await pool.query('DELETE FROM users WHERE email LIKE $1', [`%-${tag}@test.local`]);
  await pool.end();
});

const check = async (user, action) => (await authorize(user, doc.id, action)).allowed;

describe('authorize()', () => {
  test.each(['read', 'download', 'edit', 'delete', 'share'])('owner may %s', async (a) => {
    expect(await check(owner, a)).toBe(true);
  });

  test.each(['read', 'download', 'edit', 'delete', 'share'])('a stranger may NOT %s', async (a) => {
    expect(await check(stranger, a)).toBe(false);
  });

  test.each(['read', 'download', 'edit', 'delete', 'share'])('admin has no access by role alone: %s', async (a) => {
    expect(await check(admin, a)).toBe(false);
  });

  test('read grant allows read and download only', async () => {
    expect(await check(reader, 'read')).toBe(true);
    expect(await check(reader, 'download')).toBe(true);
    expect(await check(reader, 'edit')).toBe(false);
    expect(await check(reader, 'delete')).toBe(false);
    expect(await check(reader, 'share')).toBe(false);
  });

  test('edit grant allows edit but never delete or share', async () => {
    expect(await check(editor, 'edit')).toBe(true);
    expect(await check(editor, 'delete')).toBe(false);
    expect(await check(editor, 'share')).toBe(false);
  });

  test('a revoked grant gives nothing', async () => {
    expect(await check(revoked, 'read')).toBe(false);
  });

  test('an expired grant gives nothing', async () => {
    expect(await check(expired, 'read')).toBe(false);
  });

  test('revocation takes effect on the very next check', async () => {
    expect(await check(reader, 'read')).toBe(true);
    await pool.query('UPDATE grants SET revoked_at = now() WHERE document_id = $1 AND user_id = $2', [doc.id, reader.id]);
    expect(await check(reader, 'read')).toBe(false);
  });

  test('a deleted document is unreachable, even for its owner', async () => {
    await pool.query('UPDATE documents SET deleted_at = now() WHERE id = $1', [doc.id]);
    expect(await check(owner, 'read')).toBe(false);
    await pool.query('UPDATE documents SET deleted_at = NULL WHERE id = $1', [doc.id]);
  });

  test('bad input is denied, not crashed', async () => {
    expect((await authorize(owner, 'not-a-uuid', 'read')).allowed).toBe(false);
    expect((await authorize(owner, doc.id, 'fly')).allowed).toBe(false);
    expect((await authorize(null, doc.id, 'read')).allowed).toBe(false);
    expect((await authorize(owner, crypto.randomUUID(), 'read')).allowed).toBe(false);
  });
});