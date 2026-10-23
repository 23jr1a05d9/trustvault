require('dotenv').config();
const crypto = require('crypto');
const pool = require('../src/db');
const { record } = require('../src/audit');

// Builds a small but valid PDF (with a correct cross-reference table) so the
// sample documents really open in any PDF reader.
function makePdf(heading, lines) {
  const esc = (s) => s.replace(/[\\()]/g, '\\$&');
  let content = 'BT /F1 20 Tf 60 740 Td (' + esc(heading) + ') Tj ET\n';
  let y = 700;
  for (const line of lines) {
    content += 'BT /F1 12 Tf 60 ' + y + ' Td (' + esc(line) + ') Tj ET\n';
    y -= 22;
  }
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    '<< /Length ' + Buffer.byteLength(content) + ' >>\nstream\n' + content + 'endstream',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((o, i) => {
    offsets.push(Buffer.byteLength(pdf));
    pdf += i + 1 + ' 0 obj\n' + o + '\nendobj\n';
  });
  const xref = Buffer.byteLength(pdf);
  pdf += 'xref\n0 ' + (objects.length + 1) + '\n0000000000 65535 f \n';
  for (const off of offsets) pdf += String(off).padStart(10, '0') + ' 00000 n \n';
  pdf += 'trailer\n<< /Size ' + (objects.length + 1) + ' /Root 1 0 R >>\nstartxref\n' + xref + '\n%%EOF\n';
  return Buffer.from(pdf, 'latin1');
}

const SAMPLES = [
  {
    title: 'Salary letter - Ravi Kumar (sample)',
    category: 'hr',
    file: 'salary-letter.pdf',
    lines: ['SAMPLE DOCUMENT - fictional data for the TrustVault demo.', '', 'Employee: Ravi Kumar', 'Role: Software Engineer', 'Annual salary: 1,200,000 (sample figure)', 'Effective from: 1 April 2026'],
    share: { level: 'read' },
  },
  {
    title: 'Customer contract - Northwind (sample)',
    category: 'contracts',
    file: 'customer-contract.pdf',
    lines: ['SAMPLE DOCUMENT - fictional data for the TrustVault demo.', '', 'Customer: Northwind Traders', 'Term: 12 months from signature', 'Value: 48,000 (sample figure)', 'Governing law: sample jurisdiction'],
    share: { level: 'edit' },
  },
  {
    title: 'Board minutes - confidential (sample)',
    category: 'finance',
    file: 'board-minutes.pdf',
    lines: ['SAMPLE DOCUMENT - fictional data for the TrustVault demo.', '', 'Meeting: Quarterly board meeting', 'Item 1: Budget approval', 'Item 2: Acquisition discussion (restricted)', 'This document is not shared with anyone.'],
    share: null,
  },
  {
    title: 'Audit paper - regulator review (sample)',
    category: 'audit',
    file: 'audit-paper.pdf',
    lines: ['SAMPLE DOCUMENT - fictional data for the TrustVault demo.', '', 'Prepared for: External regulator', 'Scope: Access controls review', 'Access to this paper expires automatically.'],
    share: { level: 'read', days: 60 },
  },
];

async function main() {
  const o = await pool.query("SELECT id, email FROM users WHERE email = 'owner@trustvault.test' AND role = 'owner'");
  const v = await pool.query("SELECT id, email FROM users WHERE email = 'viewer@trustvault.test' AND role = 'viewer'");
  if (!o.rows[0] || !v.rows[0]) {
    console.error('Run "npm run seed" first: the demo owner and viewer accounts must exist.');
    process.exit(1);
  }
  const owner = o.rows[0];
  const viewer = v.rows[0];
  let made = 0;

  for (const s of SAMPLES) {
    const exists = await pool.query(
      'SELECT 1 FROM documents WHERE owner_id = $1 AND title = $2 AND deleted_at IS NULL',
      [owner.id, s.title]
    );
    if (exists.rows[0]) {
      console.log('Already there:', s.title);
      continue;
    }
    const buffer = makePdf(s.title, s.lines);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const doc = await client.query(
        `INSERT INTO documents (owner_id, title, category, original_filename, mime_type, size_bytes, storage_key, sha256)
         VALUES ($1, $2, $3, $4, 'application/pdf', $5, $6, $7) RETURNING id`,
        [owner.id, s.title, s.category, s.file, buffer.length, crypto.randomBytes(16).toString('hex'), sha256]
      );
      const docId = doc.rows[0].id;
      await client.query('INSERT INTO document_blobs (document_id, data) VALUES ($1, $2)', [docId, buffer]);
      await record({
        actor_id: owner.id,
        actor_email: owner.email,
        action: 'document.upload',
        outcome: 'allowed',
        document_id: docId,
        details: { size: buffer.length, mime: 'application/pdf', sha256, seeded: true },
        ip: 'seed-script',
      }, client);

      if (s.share) {
        const expires = s.share.days ? new Date(Date.now() + s.share.days * 86400000) : null;
        await client.query(
          'INSERT INTO grants (document_id, user_id, level, granted_by, expires_at) VALUES ($1, $2, $3, $4, $5)',
          [docId, viewer.id, s.share.level, owner.id, expires]
        );
        await record({
          actor_id: owner.id,
          actor_email: owner.email,
          action: 'permission.grant',
          outcome: 'allowed',
          document_id: docId,
          target_user_id: viewer.id,
          details: { level: s.share.level, expires_at: expires ? expires.toISOString() : null, previous_level: null, seeded: true },
          ip: 'seed-script',
        }, client);
      }
      await client.query('COMMIT');
      made++;
      console.log('Created:', s.title, s.share ? '(shared with the viewer: ' + s.share.level + ')' : '(private to the owner)');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
  console.log('Done.', made, 'document(s) created.');
  await pool.end();
}

main().catch((err) => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});