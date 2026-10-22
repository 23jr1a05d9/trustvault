process.env.AUTH_RATE_LIMIT = '1000'; // this file makes many login-type calls
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
const NEW_PASSWORD = 'Brand#New99';
const CODE_SHAPE = /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/;
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const users = {};
const agents = {};
let ownerCodes;
let viewerCodes;

async function mkUser(role, label) {
  const hash = await argon2.hash(PASSWORD);
  const { rows } = await pool.query(
    `INSERT INTO users (email, name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, role`,
    [`${label}-${tag}@test.local`, label, hash, role]
  );
  users[label] = rows[0];
}

async function login(label, password = PASSWORD) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ email: users[label].email, password });
  return { agent, res };
}
const loginStatus = async (label, password) =>
  (await request(app).post('/api/auth/login').send({ email: users[label].email, password })).status;
const generate = (who, password = PASSWORD) => agents[who].post('/api/auth/recovery-codes').send({ current_password: password });
const reset = (label, code, password) =>
  request(app).post('/api/auth/reset-with-code').send({ email: users[label].email, code, new_password: password });

async function countAudit(action, outcome) {
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM audit_log WHERE action = $1 AND outcome = $2', [action, outcome]);
  return rows[0].n;
}

beforeAll(async () => {
  for (const [role, label] of [['owner', 'owner'], ['viewer', 'viewer'], ['viewer', 'ghost'], ['admin', 'admin']]) {
    await mkUser(role, label);
  }
  for (const label of Object.keys(users)) {
    const { agent, res } = await login(label);
    expect(res.status).toBe(200);
    agents[label] = agent;
  }
});

afterAll(async () => {
  const ids = Object.values(users).map((u) => u.id);
  await pool.query('DELETE FROM recovery_codes WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM sessions WHERE user_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM users WHERE id = ANY($1)', [ids]);
  await pool.end();
});

describe('creating recovery codes', () => {
  test('anonymous callers get 401', async () => {
    expect((await request(app).get('/api/auth/recovery-codes')).status).toBe(401);
    expect((await request(app).post('/api/auth/recovery-codes').send({})).status).toBe(401);
  });

  test('the current password is required, and a refusal is audited', async () => {
    expect((await generate('owner', 'Wrong#Pass1')).status).toBe(400);
    expect((await agents.owner.post('/api/auth/recovery-codes').send({})).status).toBe(400);
    expect(await countAudit('auth.recovery_codes.generate', 'denied')).toBeGreaterThanOrEqual(1);
  });

  test('eight codes are shown once and stored only as hashes', async () => {
    const res = await generate('owner');
    expect(res.status).toBe(201);
    ownerCodes = res.body.codes;
    expect(ownerCodes).toHaveLength(8);
    expect(new Set(ownerCodes).size).toBe(8);
    for (const c of ownerCodes) expect(c).toMatch(CODE_SHAPE);
    expect(res.headers['cache-control']).toMatch(/no-store/);

    const plain = ownerCodes[0].replace(/-/g, '');
    const asPlain = await pool.query('SELECT count(*)::int AS n FROM recovery_codes WHERE code_hash = $1', [plain]);
    const asHash = await pool.query('SELECT count(*)::int AS n FROM recovery_codes WHERE code_hash = $1', [sha(plain)]);
    expect(asPlain.rows[0].n).toBe(0);
    expect(asHash.rows[0].n).toBe(1);
    const logged = await pool.query('SELECT count(*)::int AS n FROM audit_log WHERE details::text LIKE $1', [`%${ownerCodes[0]}%`]);
    expect(logged.rows[0].n).toBe(0);

    viewerCodes = (await generate('viewer')).body.codes;
  });

  test('the status shows how many are left', async () => {
    expect((await agents.owner.get('/api/auth/recovery-codes')).body.remaining).toBe(8);
  });

  test('making new codes replaces the old ones', async () => {
    const oldCode = ownerCodes[7];
    const fresh = await generate('owner');
    expect(fresh.status).toBe(201);
    ownerCodes = fresh.body.codes;
    expect((await reset('owner', oldCode, NEW_PASSWORD)).status).toBe(400);
    expect(await loginStatus('owner', PASSWORD)).toBe(200);
  });
});

describe('forgot password', () => {
  test('a weak password is refused and does not use up the code', async () => {
    expect((await reset('owner', ownerCodes[0], 'weak')).status).toBe(400);
    expect((await agents.owner.get('/api/auth/recovery-codes')).body.remaining).toBe(8);
  });

  test('a good reset works once, ends old logins and replaces the password', async () => {
    const res = await reset('owner', ownerCodes[0].toLowerCase(), NEW_PASSWORD); // case and dashes do not matter
    expect(res.status).toBe(200);
    expect(res.body.codes_left).toBe(7);
    expect((await reset('owner', ownerCodes[0], 'Other#Pass77')).status).toBe(400);
    expect((await agents.owner.get('/api/auth/me')).status).toBe(401);
    expect(await loginStatus('owner', PASSWORD)).toBe(401);
    expect(await loginStatus('owner', NEW_PASSWORD)).toBe(200);
  });

  test('somebody else\'s code can not reset this account', async () => {
    expect((await reset('owner', viewerCodes[0], 'Other#Pass77')).status).toBe(400);
    expect(await loginStatus('owner', NEW_PASSWORD)).toBe(200);
    expect(await loginStatus('viewer', PASSWORD)).toBe(200);
  });

  test('every kind of failure gives the same answer, so emails and codes can not be probed', async () => {
    const attempts = [
      request(app).post('/api/auth/reset-with-code').send({ email: `nobody-${tag}@test.local`, code: viewerCodes[1], new_password: 'Other#Pass77' }),
      reset('owner', 'AAAA-BBBB-CCCC', 'Other#Pass77'),
      reset('owner', 'abc', 'Other#Pass77'),
      request(app).post('/api/auth/reset-with-code').send({ email: 123, code: [], new_password: 'Other#Pass77' }),
    ];
    const results = await Promise.all(attempts);
    for (const r of results) expect(r.status).toBe(400);
    expect(new Set(results.map((r) => JSON.stringify(r.body))).size).toBe(1);
  });

  test('a locked account can not be reset', async () => {
    const codes = (await generate('ghost')).body.codes;
    await pool.query('UPDATE users SET is_active = false WHERE id = $1', [users.ghost.id]);
    expect((await reset('ghost', codes[0], 'Other#Pass77')).status).toBe(400);
  });

  test('there is no administrator route for resetting a password', async () => {
    const res = await agents.admin.post(`/api/admin/users/${users.owner.id}/reset-password`);
    expect(res.status).toBe(404);
  });

  test('resets and refusals are audited, and the chain is intact', async () => {
    expect(await countAudit('auth.password_reset', 'allowed')).toBeGreaterThanOrEqual(1);
    expect(await countAudit('auth.password_reset', 'denied')).toBeGreaterThanOrEqual(3);
    expect((await verifyChain()).ok).toBe(true);
  });
});

describe('changing your own password', () => {
  const CHANGED = 'Changed#Pw55';
  const change = (agent, current, next) => agent.post('/api/auth/change-password').send({ current_password: current, new_password: next });
  let second;

  beforeAll(async () => { second = (await login('viewer')).agent; });

  test('anonymous callers get 401', async () => {
    expect((await request(app).post('/api/auth/change-password').send({})).status).toBe(401);
  });

  test('a wrong current password, a weak new one and an unchanged one are refused', async () => {
    expect((await change(agents.viewer, 'Wrong#Pass1', CHANGED)).status).toBe(400);
    expect((await change(agents.viewer, PASSWORD, 'weak')).status).toBe(400);
    expect((await change(agents.viewer, PASSWORD, PASSWORD)).status).toBe(400);
    expect(await countAudit('auth.password_change', 'denied')).toBeGreaterThanOrEqual(1);
  });

  test('a good change ends the other logins, keeps this one and replaces the password', async () => {
    expect((await change(agents.viewer, PASSWORD, CHANGED)).status).toBe(200);
    expect((await agents.viewer.get('/api/auth/me')).status).toBe(200);
    expect((await second.get('/api/auth/me')).status).toBe(401);
    expect(await loginStatus('viewer', PASSWORD)).toBe(401);
    expect(await loginStatus('viewer', CHANGED)).toBe(200);
  });
});