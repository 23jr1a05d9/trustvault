-- USERS: one row per person. The role is only ever set by the server.
CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL UNIQUE CHECK (email = lower(email)),
  name          text NOT NULL,
  password_hash text NOT NULL,
  role          text NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
  is_active     boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- SESSIONS: who is logged in. We store a hash of the session token,
-- so even a leaked database cannot be used to hijack a session.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

-- DOCUMENTS: details about each file. The file itself lives on disk
-- under storage_key (a random name), never under the user's file name.
CREATE TABLE IF NOT EXISTS documents (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id          uuid NOT NULL REFERENCES users(id),
  title             text NOT NULL,
  category          text NOT NULL DEFAULT 'general',
  original_filename text NOT NULL,
  mime_type         text NOT NULL,
  size_bytes        bigint NOT NULL,
  storage_key       text NOT NULL UNIQUE,
  sha256            text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz
);

-- GRANTS: who was given access to which document, and at what level.
-- Revoking sets revoked_at. The row is kept as history.
CREATE TABLE IF NOT EXISTS grants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id uuid NOT NULL REFERENCES documents(id),
  user_id     uuid NOT NULL REFERENCES users(id),
  level       text NOT NULL CHECK (level IN ('read', 'edit')),
  granted_by  uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);

-- A person can have only one active grant per document.
CREATE UNIQUE INDEX IF NOT EXISTS one_active_grant
  ON grants (document_id, user_id) WHERE revoked_at IS NULL;

-- AUDIT LOG: the record of who did what, including refused attempts.
-- Each row stores a hash of the previous row, forming a chain.
-- There are no foreign keys on purpose: audit rows must survive even
-- if a user or document is later removed.
CREATE TABLE IF NOT EXISTS audit_log (
  seq            bigserial PRIMARY KEY,
  at             timestamptz NOT NULL DEFAULT now(),
  actor_id       uuid,
  actor_email    text,
  action         text NOT NULL,
  outcome        text NOT NULL CHECK (outcome IN ('allowed', 'denied')),
  document_id    uuid,
  target_user_id uuid,
  details        jsonb NOT NULL DEFAULT '{}',
  ip             text,
  prev_hash      text NOT NULL,
  row_hash       text NOT NULL
);

-- APPEND-ONLY: the database itself refuses to change or delete audit rows.
CREATE OR REPLACE FUNCTION audit_log_block_changes() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER audit_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_block_changes();

CREATE OR REPLACE TRIGGER audit_no_truncate
  BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_changes();

-- DOCUMENT_BLOBS: the file bytes, kept apart from the document details.
CREATE TABLE IF NOT EXISTS document_blobs (
  document_id uuid PRIMARY KEY REFERENCES documents(id),
  data        bytea NOT NULL
);