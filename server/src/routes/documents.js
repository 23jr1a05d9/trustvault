const { authorize } = require('../authorize');
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

const searchSchema = z.object({
  q: z.string().trim().max(100).optional(),
  owner: z.string().trim().max(100).optional(),
  category: z.string().trim().max(50).optional(),
  from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((v) => !Number.isNaN(Date.parse(v))).optional(),
  to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((v) => !Number.isNaN(Date.parse(v))).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(10000).default(0),
});

// Makes %, _ and \ in what the user typed match literally, not as wildcards.
const like = (s) => '%' + s.replace(/[\\%_]/g, '\\$&') + '%';

// LIST + SEARCH: only documents the caller owns or holds a current grant for.
// The permission filter is in the SQL, so unauthorised documents are never
// fetched, never counted and never visible through any filter.
router.get('/', async (req, res) => {
  const parsed = searchSchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid search filters' });
  const f = parsed.data;

  const params = [req.user.id];
  const where = ['d.deleted_at IS NULL', '(d.owner_id = $1 OR g.id IS NOT NULL)'];
  const next = (value) => { params.push(value); return '$' + params.length; };

  if (f.q) {
    const p = next(like(f.q));
    where.push(`(d.title ILIKE ${p} OR d.original_filename ILIKE ${p})`);
  }
  if (f.owner) where.push(`u.name ILIKE ${next(like(f.owner))}`);
  if (f.category) where.push(`lower(d.category) = lower(${next(f.category)})`);
  if (f.from) where.push(`d.created_at >= ${next(f.from)}::date`);
  if (f.to) where.push(`d.created_at < (${next(f.to)}::date + 1)`);

  const limitP = next(f.limit);
  const offsetP = next(f.offset);

  const { rows } = await pool.query(
    `SELECT d.id, d.title, d.category, d.original_filename, d.mime_type, d.size_bytes,
            d.created_at, d.owner_id, u.name AS owner_name,
            CASE WHEN d.owner_id = $1 THEN 'owner' ELSE g.level END AS access,
            count(*) OVER() AS total
       FROM documents d
       JOIN users u ON u.id = d.owner_id
       LEFT JOIN grants g
         ON g.document_id = d.id AND g.user_id = $1
        AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
      WHERE ${where.join(' AND ')}
      ORDER BY d.created_at DESC
      LIMIT ${limitP} OFFSET ${offsetP}`,
    params
  );

  res.set('X-Total-Count', String(rows[0] ? rows[0].total : 0));
  res.json(rows.map(({ total, ...doc }) => doc));
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
    version: d.version,
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


// ---------- editing ----------
const MAX_VERSIONS = 20; // earlier files kept per document

const patchSchema = z
  .object({
    title: z.string().trim().min(1).max(200).optional(),
    category: z.string().trim().min(1).max(50).optional(),
  })
  .strict() // owner_id, role and anything else in the body is rejected
  .refine((v) => v.title !== undefined || v.category !== undefined);

// Runs BEFORE the upload is read, so a stranger can not make the server buffer a file.
async function editGuard(req, res, next) {
  const result = await guard(req, res, 'edit');
  if (!result) return; // guard has already answered 404 and audited the refusal
  req.doc = result.document;
  next();
}

// CHANGE TITLE / CATEGORY. Needs the edit level (or owner).
router.patch('/:id', async (req, res) => {
  const result = await guard(req, res, 'edit');
  if (!result) return;
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Provide a title and/or a category' });
  const d = result.document;
  const title = parsed.data.title ?? d.title;
  const category = parsed.data.category ?? d.category;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const upd = await client.query(
      `UPDATE documents SET title = $2, category = $3, updated_at = now()
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING id, title, category, version, updated_at`,
      [d.id, title, category]
    );
    if (!upd.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Not found' });
    }
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'document.edit',
      outcome: 'allowed',
      document_id: d.id,
      // Which fields changed, never their values: titles can be confidential.
      details: { change: 'details', fields: Object.keys(parsed.data) },
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.json(upd.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

// REPLACE THE FILE. The old file is kept as an earlier version.
router.post('/:id/replace', editGuard, receiveFile, async (req, res) => {
  if (!req.file || req.file.buffer.length === 0) return res.status(400).json({ error: 'A file is required' });
  const buffer = req.file.buffer;
  const type = await detectType(buffer);
  if (!type || !ALLOWED[type.mime]) {
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'document.edit',
      outcome: 'denied',
      document_id: req.doc.id,
      details: { reason: 'file_type_not_allowed', claimed_type: String(req.file.mimetype).slice(0, 100) },
      ip: req.ip,
    });
    return res.status(400).json({ error: 'File type not allowed. Allowed: PDF, PNG, JPG, DOCX, XLSX' });
  }
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query(
      `SELECT version, original_filename, mime_type, size_bytes, sha256 FROM documents
        WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
      [req.doc.id]
    );
    // Check again now the file has arrived: access may have been taken away during the upload.
    const again = await authorize(req.user, req.doc.id, 'edit', client);
    if (!cur.rows[0] || !again.allowed) {
      await client.query('ROLLBACK');
      await record({
        actor_id: req.user.id,
        actor_email: req.user.email,
        action: 'document.edit',
        outcome: 'denied',
        document_id: req.doc.id,
        details: { reason: 'access_removed_during_upload' },
        ip: req.ip,
      });
      return res.status(404).json({ error: 'Not found' });
    }
    const old = cur.rows[0];

    const count = await client.query('SELECT count(*)::int AS n FROM document_versions WHERE document_id = $1', [req.doc.id]);
    if (count.rows[0].n >= MAX_VERSIONS) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This document has reached its limit of ' + MAX_VERSIONS + ' earlier versions' });
    }
    const blob = await client.query('SELECT data FROM document_blobs WHERE document_id = $1 FOR UPDATE', [req.doc.id]);
    if (!blob.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Not found' });
    }

    await client.query(
      `INSERT INTO document_versions
         (document_id, version, original_filename, mime_type, size_bytes, sha256, data, replaced_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [req.doc.id, old.version, old.original_filename, old.mime_type, old.size_bytes, old.sha256, blob.rows[0].data, req.user.id]
    );
    await client.query('UPDATE document_blobs SET data = $2 WHERE document_id = $1', [req.doc.id, buffer]);
    const upd = await client.query(
      `UPDATE documents SET original_filename = $2, mime_type = $3, size_bytes = $4, sha256 = $5,
              version = version + 1, updated_at = now()
        WHERE id = $1
        RETURNING id, title, category, original_filename, mime_type, size_bytes, version, updated_at`,
      [req.doc.id, cleanName(req.file.originalname), type.mime, buffer.length, sha256]
    );
    await record({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'document.edit',
      outcome: 'allowed',
      document_id: req.doc.id,
      details: {
        change: 'file',
        from_version: old.version,
        to_version: upd.rows[0].version,
        old_sha256: old.sha256,
        new_sha256: sha256,
        size: buffer.length,
        mime: type.mime,
      },
      ip: req.ip,
    }, client);
    await client.query('COMMIT');
    res.json(upd.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

// VERSION HISTORY: owner only, because only the owner has the 'history' action.
router.get('/:id/versions', async (req, res) => {
  const result = await guard(req, res, 'history');
  if (!result) return;
  const { rows } = await pool.query(
    `SELECT v.version, v.original_filename, v.mime_type, v.size_bytes, v.replaced_at, u.name AS replaced_by_name
       FROM document_versions v JOIN users u ON u.id = v.replaced_by
      WHERE v.document_id = $1 ORDER BY v.version DESC`,
    [result.document.id]
  );
  res.json(rows);
});

router.get('/:id/versions/:version/download', async (req, res) => {
  const result = await guard(req, res, 'history');
  if (!result) return;
  if (!/^\d{1,6}$/.test(req.params.version)) return res.status(404).json({ error: 'Not found' });
  const { rows } = await pool.query(
    'SELECT original_filename, mime_type, data FROM document_versions WHERE document_id = $1 AND version = $2',
    [result.document.id, Number(req.params.version)]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });

  await record({ // written before any byte is sent
    actor_id: req.user.id,
    actor_email: req.user.email,
    action: 'document.version_download',
    outcome: 'allowed',
    document_id: result.document.id,
    details: { version: Number(req.params.version) },
    ip: req.ip,
  });
  res.attachment(rows[0].original_filename);
  res.set({
    'Content-Type': rows[0].mime_type,
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.send(rows[0].data);
});

module.exports = router;