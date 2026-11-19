import { createHash, randomBytes, scryptSync } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { prepareMcpReportStatements } from './mcp-report-statements.js';

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

export function openStore(path, { local, username, password }) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new Database(path);
  let workspaceOwnerId;
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
      CREATE TABLE IF NOT EXISTS local_workspace (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        owner_id INTEGER NOT NULL REFERENCES users(id)
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
        access TEXT NOT NULL DEFAULT 'append' CHECK (access IN ('append', 'manage')),
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

    workspaceOwnerId = db.transaction(() => {
      if (!db.pragma('table_info(mcp_keys)').some(({ name }) => name === 'access')) {
        db.exec("ALTER TABLE mcp_keys ADD COLUMN access TEXT NOT NULL DEFAULT 'append' CHECK (access IN ('append', 'manage'))");
      }
      let owner = db.prepare(`
        SELECT users.id, users.username FROM local_workspace
        JOIN users ON users.id = local_workspace.owner_id WHERE singleton = 1
      `).get();
      if (!owner) {
        // Existing databases bootstrapped the primary admin before any other user.
        owner = db.prepare('SELECT id, username FROM users ORDER BY id LIMIT 1').get();
        if (!owner) {
          // The empty username is reserved for the workspace before organization bootstrap.
          const { lastInsertRowid: id } = db.prepare("INSERT INTO users (username, salt, password_hash) VALUES ('', '', '')").run();
          owner = { id, username: '' };
        }
        db.prepare('INSERT INTO local_workspace (singleton, owner_id) VALUES (1, ?)').run(owner.id);
      }
      if (local || owner.username !== '') return owner.id;
      if (!username || !password) {
        throw new Error('Set ADMIN_USERNAME and ADMIN_PASSWORD to initialize an empty database or promote a local workspace');
      }
      const trimmed = password.trim();
      const normalized = trimmed.toLowerCase();
      if ([...trimmed].length < 15 || normalized === username.trim().toLowerCase()
          || /^(.{1,8})\1+$/su.test(normalized) || weakBootstrapPasswords.has(normalized)) {
        throw new Error('ADMIN_PASSWORD must be at least 15 characters and avoid common passwords or placeholders. Generate a random password.');
      }
      const salt = randomBytes(16).toString('hex');
      const hash = scryptSync(password, salt, 64).toString('hex');
      db.prepare('UPDATE users SET username = ?, salt = ?, password_hash = ? WHERE id = ?')
        .run(username, salt, hash, owner.id);
      return owner.id;
    }).immediate();
  } catch (error) {
    db.close();
    throw error;
  }

  const statements = {
    ...prepareMcpReportStatements(db),
    health: db.prepare('SELECT 1'),
    user: db.prepare("SELECT * FROM users WHERE username = ? AND username <> ''"),
    session: db.prepare(`
      SELECT users.id, users.username
      FROM sessions JOIN users ON sessions.owner_id = users.id
      WHERE sessions.digest = ? AND sessions.expires_at > ? AND users.username <> ''
    `),
    deleteSession: db.prepare('DELETE FROM sessions WHERE digest = ?'),
    deleteExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
    insertSession: db.prepare('INSERT INTO sessions (digest, owner_id, expires_at) VALUES (?, ?, ?)'),
    projects: db.prepare('SELECT data, template_instructions FROM projects WHERE owner_id = ?'),
    project: db.prepare('SELECT owner_id, id, template_instructions FROM projects WHERE owner_id = ? AND id = ?'),
    projectCandidates: db.prepare('SELECT owner_id, id, template_instructions FROM projects WHERE owner_id = ? LIMIT 2'),
    putProject: db.prepare(`
      INSERT INTO projects (owner_id, id, data, template_instructions) VALUES (?, ?, ?, ?)
      ON CONFLICT (owner_id, id) DO UPDATE SET
        data = excluded.data,
        template_instructions = COALESCE(excluded.template_instructions, projects.template_instructions)
    `),
    deleteProject: db.prepare('DELETE FROM projects WHERE owner_id = ? AND id = ?'),
    findings: db.prepare('SELECT data FROM findings WHERE owner_id = ? AND project_id = ?'),
    // Older clients omit optional finding fields when saving.
    putFinding: db.prepare(`
      INSERT INTO findings (owner_id, project_id, id, data)
      SELECT owner_id, id, ?, json_patch('{}', @data) FROM projects WHERE owner_id = ? AND id = ?
      ON CONFLICT (owner_id, project_id, id) DO UPDATE SET data = json_patch(findings.data, @data)
    `),
    deleteFinding: db.prepare('DELETE FROM findings WHERE owner_id = ? AND project_id = ? AND id = ?'),
    insertFinding: db.prepare('INSERT INTO findings (owner_id, project_id, id, data) VALUES (?, ?, ?, ?)'),
    keys: db.prepare(`
      SELECT id, name, created_at AS createdAt, access FROM mcp_keys
      WHERE owner_id = ? AND project_id = ? ORDER BY created_at, id
    `),
    insertKey: db.prepare(`
      INSERT INTO mcp_keys (owner_id, project_id, id, name, created_at, digest, access)
      SELECT owner_id, id, ?, ?, ?, ?, ? FROM projects WHERE owner_id = ? AND id = ?
    `),
    deleteKey: db.prepare('DELETE FROM mcp_keys WHERE owner_id = ? AND project_id = ? AND id = ?'),
    mcpProject: db.prepare(`
      SELECT projects.owner_id, projects.id, projects.template_instructions, mcp_keys.id AS key_id, mcp_keys.access
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
    workspaceOwnerId,
    close: () => db.close(),
    createSession: db.transaction((ownerId, token, previousToken) => {
      const now = Date.now();
      statements.deleteExpiredSessions.run(now);
      if (previousToken) statements.deleteSession.run(digest(previousToken));
      statements.insertSession.run(digest(token), ownerId, now + sessionDuration);
      return sessionDuration;
    }).immediate,
    appendFinding: db.transaction((selectProject, idempotencyKey, inputDigest, makeFinding) => {
      const project = selectProject();
      if (project.error) return project;
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
