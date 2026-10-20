require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const pool = require('./db');
const authRoutes = require('./routes/auth');
const documentRoutes = require('./routes/documents');
const grantRoutes = require('./routes/grants');
const adminRoutes = require('./routes/admin');

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ ok: false });
  }
});

app.use('/api/auth', authRoutes);
app.use('/api/documents/:id/grants', grantRoutes); // before the documents router
app.use('/api/documents', documentRoutes);
app.use('/api/admin', adminRoutes);

app.get('/', (req, res) => {
  res.json({ name: 'TrustVault API', status: 'ok' });
});
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Last resort: never show internal details to the caller.
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON' });
  }
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

module.exports = app;