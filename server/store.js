import { createHash, randomBytes, scryptSync } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';

const sessionDuration = 7 * 24 * 60 * 60 * 1000;
const weakBootstrapPasswords = new Set([
  '123456789012345',
  '1234567890123456',
  'correcthorsebatterystaple',
  'password123456789',
  'qwertyuiopasdfgh',
  'replace-with-a-strong-password',
]);

export function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function openStore(path, username, password) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new Database(path);
  try {
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        digest TEXT PRIMARY KEY,
        owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
      CREATE TABLE IF NOT EXISTS projects (
        owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        data TEXT NOT NULL,
        template_instructions TEXT,
        PRIMARY KEY (owner_id, id)
      );
      CREATE TABLE IF NOT EXISTS findings (
        owner_id INTEGER NOT NULL,
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (owner_id, project_id, id),
        FOREIGN KEY (owner_id, project_id) REFERENCES projects(owner_id, id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS mcp_keys (
        owner_id INTEGER NOT NULL,
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        digest TEXT NOT NULL UNIQUE,
        PRIMARY KEY (owner_id, project_id, id),
        FOREIGN KEY (owner_id, project_id) REFERENCES projects(owner_id, id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS mcp_appends (
        owner_id INTEGER NOT NULL,
        project_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        input_digest TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        PRIMARY KEY (owner_id, project_id, idempotency_key),
        FOREIGN KEY (owner_id, project_id) REFERENCES projects(owner_id, id) ON DELETE CASCADE
      );
    `);

    db.transaction(() => {
      if (db.prepare('SELECT 1 FROM users LIMIT 1').get()) return;
      if (!username || !password) {
        throw new Error('Set ADMIN_USERNAME and ADMIN_PASSWORD to initialize an empty database');
      }
      const trimmed = password.trim();
      const normalized = trimmed.toLowerCase();
      if ([...trimmed].length < 15 || normalized === username.trim().toLowerCase()
          || /^(.{1,8})\1+$/su.test(normalized) || weakBootstrapPasswords.has(normalized)) {
        throw new Error('ADMIN_PASSWORD must be at least 15 characters and avoid common passwords or placeholders. Generate a random password.');
      }
      const salt = randomBytes(16).toString('hex');
      const hash = scryptSync(password, salt, 64).toString('hex');
      db.prepare('INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)').run(username, salt, hash);
    }).immediate();
  } catch (error) {
    db.close();
    throw error;
  }

  const statements = {
    health: db.prepare('SELECT 1'),
    user: db.prepare('SELECT * FROM users WHERE username = ?'),
    session: db.prepare(`
      SELECT users.id, users.username
      FROM sessions JOIN users ON sessions.owner_id = users.id
      WHERE sessions.digest = ? AND sessions.expires_at > ?
    `),
    deleteSession: db.prepare('DELETE FROM sessions WHERE digest = ?'),
    deleteExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
    insertSession: db.prepare('INSERT INTO sessions (digest, owner_id, expires_at) VALUES (?, ?, ?)'),
    projects: db.prepare('SELECT data, template_instructions FROM projects WHERE owner_id = ?'),
    project: db.prepare('SELECT 1 FROM projects WHERE owner_id = ? AND id = ?'),
    putProject: db.prepare(`
      INSERT INTO projects (owner_id, id, data, template_instructions) VALUES (?, ?, ?, ?)
      ON CONFLICT (owner_id, id) DO UPDATE SET
        data = excluded.data,
        template_instructions = COALESCE(excluded.template_instructions, projects.template_instructions)
    `),
    deleteProject: db.prepare('DELETE FROM projects WHERE owner_id = ? AND id = ?'),
    findings: db.prepare('SELECT data FROM findings WHERE owner_id = ? AND project_id = ?'),
    putFinding: db.prepare(`
      INSERT INTO findings (owner_id, project_id, id, data)
      SELECT owner_id, id, ?, ? FROM projects WHERE owner_id = ? AND id = ?
      ON CONFLICT (owner_id, project_id, id) DO UPDATE SET data = excluded.data
    `),
    deleteFinding: db.prepare('DELETE FROM findings WHERE owner_id = ? AND project_id = ? AND id = ?'),
    insertFinding: db.prepare('INSERT INTO findings (owner_id, project_id, id, data) VALUES (?, ?, ?, ?)'),
    keys: db.prepare(`
      SELECT id, name, created_at AS createdAt FROM mcp_keys
      WHERE owner_id = ? AND project_id = ? ORDER BY created_at, id
    `),
    insertKey: db.prepare(`
      INSERT INTO mcp_keys (owner_id, project_id, id, name, created_at, digest)
      SELECT owner_id, id, ?, ?, ?, ? FROM projects WHERE owner_id = ? AND id = ?
    `),
    deleteKey: db.prepare('DELETE FROM mcp_keys WHERE owner_id = ? AND project_id = ? AND id = ?'),
    mcpProject: db.prepare(`
      SELECT projects.owner_id, projects.id, projects.template_instructions, mcp_keys.id AS key_id
      FROM mcp_keys JOIN projects
        ON projects.owner_id = mcp_keys.owner_id AND projects.id = mcp_keys.project_id
      WHERE mcp_keys.digest = ?
    `),
    previousAppend: db.prepare(`
      SELECT input_digest, finding_id FROM mcp_appends
      WHERE owner_id = ? AND project_id = ? AND idempotency_key = ?
    `),
    insertAppend: db.prepare('INSERT INTO mcp_appends VALUES (?, ?, ?, ?, ?)'),
  };

  return {
    statements,
    close: () => db.close(),
    createSession: db.transaction((ownerId, token, previousToken) => {
      const now = Date.now();
      statements.deleteExpiredSessions.run(now);
      if (previousToken) statements.deleteSession.run(digest(previousToken));
      statements.insertSession.run(digest(token), ownerId, now + sessionDuration);
      return sessionDuration;
    }).immediate,
    appendFinding: db.transaction((keyDigest, idempotencyKey, inputDigest, makeFinding) => {
      const project = statements.mcpProject.get(keyDigest);
      if (!project) return { error: 'Invalid or revoked project key' };
      const { owner_id: ownerId, id: projectId } = project;
      const previous = statements.previousAppend.get(ownerId, projectId, idempotencyKey);
      if (previous) {
        if (previous.input_digest !== inputDigest) {
          return { error: 'idempotencyKey already used with different finding content' };
        }
        return { findingId: previous.finding_id, created: false };
      }
      const finding = makeFinding(projectId);
      statements.insertFinding.run(ownerId, projectId, finding.id, JSON.stringify(finding));
      statements.insertAppend.run(ownerId, projectId, idempotencyKey, inputDigest, finding.id);
      return { findingId: finding.id, created: true };
    }).immediate,
  };
}
