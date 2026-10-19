require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const pool = require('./db');

const app = express();
app.use(helmet());
app.use(express.json());

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ ok: false });
  }
});

module.exports = app;