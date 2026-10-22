require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const pool = require('./db');
const authRoutes = require('./routes/auth');
const documentRoutes = require('./routes/documents');
const grantRoutes = require('./routes/grants');
const directoryRoutes = require('./routes/directory');
const adminRoutes = require('./routes/admin');

const app = express();
app.set('trust proxy', 1);
app.use(helmet()); // its default policy blocks inline scripts, so a script injected into a page can not run
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
app.use('/api/directory', directoryRoutes);
app.use('/api/admin', adminRoutes);

// The web page. Only the public folder is served, and it holds no secrets.
app.use(express.static(path.join(__dirname, '..', 'public')));

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