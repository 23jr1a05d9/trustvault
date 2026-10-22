require('dotenv').config();
const crypto = require('crypto');
const request = require('supertest');
const app = require('../src/app');
const pool = require('../src/db');

const tag = crypto.randomBytes(4).toString('hex');
const emailOf = (n) => `${n}-${tag}@test.local`;

afterAll(async () => {
  await pool.query('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE $1)', [`%-${tag}@test.local`]);
  await pool.query('DELETE FROM users WHERE email LIKE $1', [`%-${tag}@test.local`]);
  await pool.end();
});

const register = (n, password, extra = {}) =>
  request(app).post('/api/auth/register').send({ email: emailOf(n), name: 'Pw Test', password, ...extra });

test.each([
  ['is too short', 'Ab1!x'],
  ['has no uppercase letter', 'abcdef1!'],
  ['has no lowercase letter', 'ABCDEF1!'],
  ['has no number', 'Abcdef!!'],
  ['has no special character', 'Abcdef12'],
])('a password that %s is refused by the server', async (_why, password) => {
  const res = await register('weak', password);
  expect(res.status).toBe(400);
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM users WHERE email = $1', [emailOf('weak')]);
  expect(rows[0].n).toBe(0);
});

test('a password meeting every rule is accepted', async () => {
  const res = await register('good', 'Abcd1!');
  expect(res.status).toBe(201);
});

test('sending role: admin in the form does not make the account an admin', async () => {
  const res = await register('sneaky', 'Abcd1!', { role: 'admin' });
  expect(res.status).toBe(201);
  const { rows } = await pool.query('SELECT role FROM users WHERE email = $1', [emailOf('sneaky')]);
  expect(rows[0].role).toBe('pending');
});