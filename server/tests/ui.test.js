require('dotenv').config();
const request = require('supertest');
const app = require('../src/app');
const pool = require('../src/db');

afterAll(() => pool.end());

test('the home page is served without login, with a strict script policy', async () => {
  const res = await request(app).get('/');
  expect(res.status).toBe(200);
  expect(res.headers['content-type']).toMatch(/html/);
  const csp = res.headers['content-security-policy'];
  expect(csp).toMatch(/script-src 'self'/);
  expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
});

test('the API still needs a login', async () => {
  expect((await request(app).get('/api/documents')).status).toBe(401);
});

test('server files are not exposed through the web page', async () => {
  for (const p of ['/.env', '/package.json', '/src/app.js', '/tests/ui.test.js']) {
    expect((await request(app).get(p)).status).toBe(404);
  }
});