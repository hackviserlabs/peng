import { randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { parseCookie } from 'cookie';
import express from 'express';
import { createLoginLimiter } from './login-limiter.js';
import { createMcpEndpoint } from './mcp.js';
import * as schemas from './schemas.js';
import { digest, openStore } from './store.js';

const deriveKey = promisify(scrypt);
const dummySalt = randomBytes(16).toString('hex');
const dummyHash = Buffer.alloc(64);
const newToken = () => randomBytes(32).toString('base64url');
const notFound = (res) => res.status(404).json({ error: 'Not found' });
const unauthorized = (res) => res.status(401).json({ error: 'Unauthorized' });
const invalidBody = (res) => res.status(400).json({ error: 'Invalid request body' });

function parseOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('APP_ORIGIN must be an HTTP(S) origin');
  }
  return url;
}

export function createApp({
  databasePath,
  adminUsername,
  adminPassword,
  cookieSecure = true,
  appOrigin,
}) {
  const publicOrigin = appOrigin ? parseOrigin(appOrigin) : undefined;
  if ((adminUsername !== undefined || adminPassword !== undefined)
      && !schemas.credentials.safeParse({ username: adminUsername, password: adminPassword }).success) {
    throw new Error('Provide both valid ADMIN_USERNAME and ADMIN_PASSWORD values');
  }

  const store = openStore(databasePath, adminUsername, adminPassword);
  const { statements } = store;
  const mcp = createMcpEndpoint(store);
  const app = express();
  app.disable('x-powered-by');

  const loginLimiter = createLoginLimiter();
  const cookieOptions = { httpOnly: true, sameSite: 'strict', secure: cookieSecure, path: '/api' };
  const loginJson = express.json({ limit: '8kb' });
  const apiJson = express.json({ limit: '16mb' });

  function requestOrigin(req) {
    // Use the configured public origin when TLS terminates at the proxy.
    const authority = req.get('host');
    if (!authority) return;
    try {
      const url = parseOrigin(`${publicOrigin?.protocol ?? 'http:'}//${authority}`);
      if (!publicOrigin || url.host === publicOrigin.host) return url.origin;
    } catch {
      // Reject malformed Host values.
    }
  }

  app.get('/healthz', (_req, res) => {
    statements.health.get();
    res.json({ status: 'ok' });
  });

  const api = express.Router();
  app.use('/api', api);
  api.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    const origin = requestOrigin(req);
    if (!origin || (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('origin') !== origin)) {
      return res.status(403).json({ error: 'Invalid request origin' });
    }
    // Host-only cookies are shared between ports. Use the public origin for the name.
    req.sessionCookie = `peng_session_${digest(origin).slice(0, 16)}`;
    const token = parseCookie(req.get('cookie') ?? '')[req.sessionCookie];
    if (/^[A-Za-z0-9_-]{43}$/.test(token ?? '')) req.sessionToken = token;
    next();
  });

  api.post('/login', loginJson, async (req, res) => {
    const parsed = schemas.credentials.safeParse(req.body);
    if (!parsed.success) return invalidBody(res);
    const { username, password } = parsed.data;
    const retryAfter = loginLimiter.acquire(req.socket.remoteAddress);
    if (retryAfter) {
      return res.set('Retry-After', String(retryAfter)).status(429).json({ error: 'Too many login attempts. Try again later.' });
    }
    try {
      const user = statements.user.get(username);
      const candidate = await deriveKey(password, user?.salt ?? dummySalt, 64);
      const expected = user ? Buffer.from(user.password_hash, 'hex') : dummyHash;
      if (!timingSafeEqual(candidate, expected) || !user) return unauthorized(res);

      const token = newToken();
      const maxAge = store.createSession(user.id, token, req.sessionToken);
      res.cookie(req.sessionCookie, token, { ...cookieOptions, maxAge }).json({ username: user.username });
    } finally {
      loginLimiter.release();
    }
  });

  api.post('/logout', (req, res) => {
    if (req.sessionToken) statements.deleteSession.run(digest(req.sessionToken));
    res.clearCookie(req.sessionCookie, cookieOptions).status(204).end();
  });

  api.use((req, res, next) => {
    const user = req.sessionToken && statements.session.get(digest(req.sessionToken), Date.now());
    if (!user) return unauthorized(res);
    req.user = user;
    next();
  });

  api.get('/session', (req, res) => res.json({ username: req.user.username }));

  api.get('/projects', (req, res) => {
    res.json(statements.projects.all(req.user.id).map(({ data, template_instructions }) => {
      const project = JSON.parse(data);
      if (template_instructions !== null) project.templateInstructions = template_instructions;
      return project;
    }));
  });

  api.put('/projects/:id', apiJson, (req, res) => {
    const parsed = schemas.project.safeParse(req.body);
    if (!parsed.success || parsed.data.id !== req.params.id) return invalidBody(res);
    const { id, templateInstructions, ...data } = parsed.data;
    statements.putProject.run(req.user.id, id, JSON.stringify({ id, ...data }), templateInstructions ?? null);
    res.status(204).end();
  });

  api.delete('/projects/:id', (req, res) => {
    statements.deleteProject.run(req.user.id, req.params.id);
    res.status(204).end();
  });

  const project = express.Router({ mergeParams: true });
  api.use('/projects/:id', project);
  project.use((req, res, next) => {
    if (!statements.project.get(req.user.id, req.params.id)) return notFound(res);
    next();
  });

  project.get('/findings', (req, res) => {
    res.json(statements.findings.all(req.user.id, req.params.id).map(({ data }) => JSON.parse(data)));
  });

  project.put('/findings/:findingId', apiJson, (req, res) => {
    const { id, findingId } = req.params;
    const parsed = schemas.finding.safeParse(req.body);
    if (!parsed.success || parsed.data.id !== findingId || parsed.data.projectId !== id) return invalidBody(res);
    const inserted = statements.putFinding.run(findingId, JSON.stringify(parsed.data), req.user.id, id);
    if (!inserted.changes) return notFound(res);
    res.status(204).end();
  });

  project.delete('/findings/:findingId', (req, res) => {
    statements.deleteFinding.run(req.user.id, req.params.id, req.params.findingId);
    res.status(204).end();
  });

  project.get('/keys', (req, res) => {
    res.json(statements.keys.all(req.user.id, req.params.id));
  });

  project.post('/keys', loginJson, (req, res) => {
    const parsed = schemas.keyRequest.safeParse(req.body);
    if (!parsed.success) return invalidBody(res);
    const key = `peng_${newToken()}`;
    const { changes } = statements.insertKey.run(
      randomUUID(), parsed.data.name, new Date().toISOString(), digest(key), req.user.id, req.params.id,
    );
    if (!changes) return notFound(res);
    res.status(201).json({ key });
  });

  project.delete('/keys/:keyId', (req, res) => {
    statements.deleteKey.run(req.user.id, req.params.id, req.params.keyId);
    res.status(204).end();
  });

  app.all('/mcp', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    const origin = requestOrigin(req);
    if (!origin || (req.get('origin') !== undefined && req.get('origin') !== origin)) {
      return res.status(403).json({ error: 'Invalid request origin' });
    }
    const token = /^Bearer (peng_[A-Za-z0-9_-]{43})$/i.exec(req.get('authorization') ?? '')?.[1];
    const keyDigest = token && digest(token);
    const key = keyDigest && statements.mcpProject.get(keyDigest);
    if (!key) {
      res.set('WWW-Authenticate', 'Bearer realm="peng"');
      return unauthorized(res);
    }
    req.auth = { token, clientId: key.key_id, scopes: ['findings:append', 'templates:read'], extra: { keyDigest } };
    next();
  }, mcp.handle);

  app.use((_req, res) => notFound(res));
  app.use((error, _req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.status === 400) return invalidBody(res);
    if (error.status === 413) return res.status(413).json({ error: 'Request body too large' });
    if (error.status === 415) return res.status(415).json({ error: 'Unsupported request encoding' });
    console.error('Backend request failed', error);
    res.status(500).json({ error: 'Internal server error' });
  });

  return {
    app,
    close: async () => {
      await mcp.close();
      store.close();
    },
  };
}
