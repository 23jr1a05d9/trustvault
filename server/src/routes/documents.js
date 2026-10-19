const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const FileType = require('file-type');
const { z } = require('zod');
const pool = require('../db');
const { requireAuth } = require('../auth');
const { record } = require('../audit');
const { guard } = require('../guard');

const router = express.Router();

// Nothing in this file works without a valid login.
router.use(requireAuth);

const MAX_BYTES = 10 * 1024 * 1024;

// Allowlist, keyed by the REAL type found from the file's first bytes.
const ALLOWED = {
  'application/pdf': 'pdf',
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1, fields: 5 },
});

// Runs AFTER requireAuth, so strangers cannot make the server buffer uploads.
function receiveFile(req, res, next) {
  upload.single('file')(req, res, (err) => {
    if (!err) return next();
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large (max 10 MB)' });
    }
    return res.status(400).json({ error: 'Upload failed' });
  });
}

const metaSchema = z.object({
  title: z.string().trim().min(1).max(200),
  category: z.string().trim().min(1).max(50).default('general'),
});

// Reads the first bytes of the file to find its real type.
async function detectType(buffer) {
  return FileType.fromBuffer(buffer);
}

// The name is kept for display only. It never decides a path or a type.
function cleanName(name) {
  const cleaned = String(name || 'file').replace(/[\x00-\x1f\x7f\\/]/g, '_').slice(0, 200);
  return cleaned || 'file';
}

async function ownersOnly(req, res, next) {
  if (req.user.role === 'owner') return next();
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'document.upload',
    outcome: 'denied',
    details: { reason: 'role_not_allowed', role: req.user.role },
    ip: req.ip,
  });
  res.status(403).json({ error: 'Only document owners can upload' });
}

// UPLOAD
router.post('/', ownersOnly, receiveFile, async (req, res) => {
  const meta = metaSchema.safeParse(req.body);
  if (!req.file || req.file.buffer.length === 0 || !meta.success) {
    return res.status(400).json({ error: 'A file and a title (1-200 characters) are required' });
  }

  const buffer = req.file.buffer;
  const type = await detectType(buffer);
  if (!type || !ALLOWED[type.mime]) {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'document.upload',
      outcome: 'denied',
      details: { reason: 'file_type_not_allowed', claimed_type: String(req.file.mimetype).slice(0, 100) },
      ip: req.ip,
    });
    return res.status(400).json({ error: 'File type not allowed. Allowed: PDF, PNG, JPG, DOCX, XLSX' });
  }

  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // owner_id comes from the logged-in user, NEVER from the request body.
    const { rows } = await client.query(
      `INSERT INTO documents
         (owner_id, title, category, original_filename, mime_type, size_bytes, storage_key, sha256)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, title, category, original_filename, mime_type, size_bytes, created_at`,
      [req.user.id, meta.data.title, meta.data.category, cleanName(req.file.originalname),
       type.mime, buffer.length, crypto.randomBytes(16).toString('hex'), sha256]
    );
    await client.query('INSERT INTO document_blobs (document_id, data) VALUES ($1, $2)', [rows[0].id, buffer]);
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'document.upload',
      outcome: 'allowed',
      document_id: rows[0].id,
      details: { size: buffer.length, mime: type.mime, sha256 },
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

// LIST: only documents the caller owns or holds a current grant for.
// The permission filter is inside the query, so nothing else is ever fetched.
router.get('/', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT d.id, d.title, d.category, d.original_filename, d.mime_type, d.size_bytes,
            d.created_at, d.owner_id, u.name AS owner_name,
            CASE WHEN d.owner_id = $1 THEN 'owner' ELSE g.level END AS access
       FROM documents d
       JOIN users u ON u.id = d.owner_id
       LEFT JOIN grants g
         ON g.document_id = d.id AND g.user_id = $1
        AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
      WHERE d.deleted_at IS NULL AND (d.owner_id = $1 OR g.id IS NOT NULL)
      ORDER BY d.created_at DESC
      LIMIT 200`,
    [req.user.id]
  );
  res.json(rows);
});

// DETAILS
router.get('/:id', async (req, res) => {
  const result = await guard(req, res, 'read');
  if (!result) return;
  const d = result.document;
  res.json({
    id: d.id, title: d.title, category: d.category,
    original_filename: d.original_filename, mime_type: d.mime_type,
    size_bytes: d.size_bytes, owner_id: d.owner_id,
    created_at: d.created_at, updated_at: d.updated_at,
    access: result.via,
  });
});

// DOWNLOAD: the authorisation decision for opening a file is the guard() line.
router.get('/:id/download', async (req, res) => {
  const result = await guard(req, res, 'download');
  if (!result) return;

  const blob = await pool.query('SELECT data FROM document_blobs WHERE document_id = $1', [result.document.id]);
  if (!blob.rows[0]) return res.status(404).json({ error: 'Not found' });

  // Written BEFORE any byte is sent. If the audit write fails, nothing is sent.
  await record({
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'document.download',
    outcome: 'allowed',
    document_id: result.document.id,
    details: { via: result.via },
    ip: req.ip,
  });

  res.attachment(result.document.original_filename); // forces "save as", never "open in page"
  res.set({
    'Content-Type': result.document.mime_type, // the real type we detected, not the client's claim
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.send(blob.rows[0].data);
});

// DELETE (soft: the row is kept, but nobody can reach it any more)
router.delete('/:id', async (req, res) => {
  const result = await guard(req, res, 'delete');
  if (!result) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'UPDATE documents SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL',
      [result.document.id]
    );
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'document.delete',
      outcome: 'allowed',
      document_id: result.document.id,
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

module.exports = router;