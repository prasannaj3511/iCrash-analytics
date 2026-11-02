-- iCrash Analytics schema. Idempotent: safe to run repeatedly.
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL,
  name          TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('superadmin', 'user')),
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at    BIGINT NOT NULL,
  last_login_at BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq ON users (lower(email));

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_exp_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS projects (
  id         BIGSERIAL PRIMARY KEY,
  owner_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  platform   TEXT NOT NULL DEFAULT 'javascript',
  public_key TEXT NOT NULL UNIQUE,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS projects_owner_idx ON projects (owner_id);

CREATE TABLE IF NOT EXISTS issues (
  id           BIGSERIAL PRIMARY KEY,
  project_id   BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint  TEXT NOT NULL,
  type         TEXT,
  title        TEXT NOT NULL,
  culprit      TEXT,
  level        TEXT NOT NULL DEFAULT 'error',
  status       TEXT NOT NULL DEFAULT 'unresolved' CHECK (status IN ('unresolved', 'resolved', 'ignored')),
  first_seen   BIGINT NOT NULL,
  last_seen    BIGINT NOT NULL,
  count        BIGINT NOT NULL DEFAULT 1,
  users        BIGINT NOT NULL DEFAULT 0,
  last_release TEXT,
  last_env     TEXT,
  UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS issues_project_idx ON issues (project_id, status, last_seen DESC);

CREATE TABLE IF NOT EXISTS events (
  id          BIGSERIAL PRIMARY KEY,
  issue_id    BIGINT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
  project_id  BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  ts          BIGINT NOT NULL,
  environment TEXT,
  release     TEXT,
  user_key    TEXT,
  payload     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_issue_idx ON events (issue_id, id DESC);
CREATE INDEX IF NOT EXISTS events_project_ts_idx ON events (project_id, ts);

-- Extra alert recipients per project (the project owner always receives alerts as well).
CREATE TABLE IF NOT EXISTS project_recipients (
  id         BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS project_recipients_uq ON project_recipients (project_id, lower(email));

-- Users who share a project with its owner (they can view it and triage issues, but not manage it).
CREATE TABLE IF NOT EXISTS project_members (
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  added_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (project_id, user_id)
);
CREATE INDEX IF NOT EXISTS project_members_user_idx ON project_members (user_id);
