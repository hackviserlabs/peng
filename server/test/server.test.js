import assert from 'node:assert/strict';
import { scryptSync } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import Database from 'better-sqlite3';
import { ALL_TEMPLATES } from '../../src/data/templates/index.ts';
import { createDefaultFinding, createDefaultProject } from '../../src/types/index.ts';
import { createApp } from '../app.js';
import { createLoginLimiter } from '../login-limiter.js';
import { digest } from '../store.js';

const admin = { adminUsername: 'admin', adminPassword: 'test fixture password only' };

async function runServer(t, options = {}) {
  const backend = createApp({ databasePath: ':memory:', cookieSecure: false, ...admin, ...options });
  const server = backend.app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await backend.close();
  };
  t.after(stop);

  function request(path, { method = 'GET', body, cookie, headers = {} } = {}) {
    return fetch(origin + path, {
      method,
      headers: {
        ...(method === 'GET' ? {} : { Origin: origin }),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(cookie ? { Cookie: cookie } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  async function login(username = admin.adminUsername, password = admin.adminPassword) {
    const response = await request('/api/login', {
      method: 'POST',
      body: { username, password },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { username });
    const setCookie = response.headers.get('set-cookie');
    return { setCookie, cookie: setCookie.split(';')[0] };
  }

  return { request, login, origin, stop };
}

async function addKey(request, path, cookie, name) {
  const response = await request(path + '/keys', { method: 'POST', cookie, body: { name } });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.deepEqual(Object.keys(body), ['key']);
  return body.key;
}

async function connectMcp(t, origin, key, mode = 'legacy') {
  const client = new Client({ name: 'integration-test', version: '1.0.0' }, { versionNegotiation: { mode } });
  const transport = new StreamableHTTPClientTransport(new URL('/mcp', origin), {
    requestInit: { headers: { Authorization: `Bearer ${key}` } },
  });
  t.after(() => client.close());
  await client.connect(transport);
  return client;
}

function databasePath(t) {
  return mkdtemp(join(tmpdir(), 'peng-server-')).then((directory) => {
    t.after(() => rm(directory, { recursive: true, force: true }));
    return join(directory, 'peng.sqlite3');
  });
}

test('health, session cookie, login CSRF, rotation and logout', async (t) => {
  const { request, login, origin } = await runServer(t, { cookieSecure: true });
  assert.deepEqual(await (await request('/healthz')).json(), { status: 'ok' });
  assert.equal((await request('/api/session')).status, 401);
  const credentials = { username: admin.adminUsername, password: admin.adminPassword };
  assert.equal((await fetch(origin + '/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials),
  })).status, 403);
  assert.equal((await request('/api/login', {
    method: 'POST', body: credentials, headers: { Origin: 'https://other.example' },
  })).status, 403);
  assert.equal((await request('/api/login', {
    method: 'POST', body: { ...credentials, password: 'wrong' },
  })).status, 401);

  const { cookie, setCookie } = await login();
  for (const attribute of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/api', 'Max-Age=604800']) {
    assert.ok(setCookie.split('; ').includes(attribute), setCookie);
  }
  assert.deepEqual(await (await request('/api/session', { cookie })).json(), { username: 'admin' });

  const renewal = await request('/api/login', { method: 'POST', body: credentials, cookie });
  assert.equal(renewal.status, 200);
  const renewedCookie = renewal.headers.get('set-cookie').split(';')[0];
  assert.notEqual(renewedCookie, cookie);
  assert.equal((await request('/api/session', { cookie })).status, 401);
  assert.equal((await request('/api/logout', {
    method: 'POST', cookie: renewedCookie, headers: { Origin: origin + '.invalid' },
  })).status, 403);
  const logout = await request('/api/logout', { method: 'POST', cookie: renewedCookie });
  assert.equal(logout.status, 204);
  assert.equal(logout.headers.get('set-cookie').split(';')[0], `${renewedCookie.split('=')[0]}=`);
  assert.equal((await request('/api/session', { cookie: renewedCookie })).status, 401);
});

test('login limits attempts across usernames and returns Retry-After without changing sessions', async (t) => {
  const { request, login } = await runServer(t);
  const { cookie } = await login();
  for (let attempt = 0; attempt < 7; attempt++) {
    const rejected = await request('/api/login', {
      method: 'POST', body: { username: attempt === 0 ? admin.adminUsername : `unknown-${attempt}`, password: 'wrong' },
    });
    assert.equal(rejected.status, 401);
    assert.deepEqual(await rejected.json(), { error: 'Unauthorized' });
  }
  const limited = await request('/api/login', {
    method: 'POST', cookie, body: { username: admin.adminUsername, password: admin.adminPassword },
  });
  assert.equal(limited.status, 429);
  const retryAfter = Number(limited.headers.get('retry-after'));
  assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60);
  assert.equal(limited.headers.get('set-cookie'), null);
  assert.equal((await request('/api/session', { cookie })).status, 200);
});

test('login limiter caps concurrent work and has a global budget that expires', () => {
  let now = 0;
  const limiter = createLoginLimiter(() => now);
  assert.equal(limiter.acquire('peer-a'), 0);
  assert.equal(limiter.acquire('peer-b'), 0);
  assert.equal(limiter.acquire('peer-c'), 1);
  limiter.release();
  assert.equal(limiter.acquire('peer-c'), 0);
  limiter.release();
  limiter.release();

  for (let i = 3; i < 30; i++) {
    assert.equal(limiter.acquire(`peer-${i}`), 0);
    limiter.release();
  }
  assert.equal(limiter.acquire('new-peer'), 60);
  now = 59_999;
  assert.equal(limiter.acquire('new-peer'), 1);
  now = 60_000;
  assert.equal(limiter.acquire('new-peer'), 0);
  assert.equal(limiter.acquire('another-peer'), 0);
  now = 120_000;
  assert.equal(limiter.acquire('new-peer'), 1);
  limiter.release();
  assert.equal(limiter.acquire('new-peer'), 0);
  limiter.release();
  limiter.release();
});

test('local servers on different ports can log in and out with a shared browser cookie jar', async (t) => {
  const path = await databasePath(t);
  const first = await runServer(t, { databasePath: path });
  const second = await runServer(t, { databasePath: path });
  const { cookie } = await first.login();
  assert.match(cookie, /^peng_session_[a-f0-9]{16}=/);
  assert.equal((await second.request('/api/session', { cookie })).status, 401);
  const { cookie: secondCookie } = await second.login();
  assert.notEqual(cookie.split('=')[0], secondCookie.split('=')[0]);
  const headers = { cookie: `${cookie}; ${secondCookie}` };
  assert.equal((await first.request('/api/session', headers)).status, 200);
  assert.equal((await second.request('/api/session', headers)).status, 200);
  assert.equal((await second.request('/api/logout', { ...headers, method: 'POST' })).status, 204);
  assert.equal((await second.request('/api/session', headers)).status, 401);
  assert.equal((await first.request('/api/session', headers)).status, 200);
});

test('configured public HTTPS origin works behind a proxy that preserves Host', async (t) => {
  const appOrigin = 'https://reports.example:8443';
  const { request, origin } = await runServer(t, { appOrigin });
  function forwarded(path, { method = 'GET', body, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      const outgoing = httpRequest(origin + path, {
        method,
        headers: { Host: new URL(appOrigin).host, ...headers },
      }, (incoming) => {
        incoming.resume();
        resolve(incoming);
      });
      outgoing.once('error', reject);
      outgoing.end(body);
    });
  }
  const login = await forwarded('/api/login', {
    method: 'POST',
    headers: { Origin: appOrigin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: admin.adminUsername, password: admin.adminPassword }),
  });
  assert.equal(login.statusCode, 200);
  const cookie = login.headers['set-cookie'][0].split(';')[0];
  assert.equal((await request('/api/session', { cookie })).status, 403);
  assert.equal((await forwarded('/api/session', { headers: { Cookie: cookie } })).statusCode, 200);
  assert.equal((await forwarded('/api/logout', {
    method: 'POST', headers: { Cookie: cookie, Origin: 'http://reports.example:8443' },
  })).statusCode, 403);
});

test('owner-scoped project, finding and key APIs persist across restarts', async (t) => {
  const path = await databasePath(t);
  const first = await runServer(t, { databasePath: path });
  const project = { ...createDefaultProject('Assessment'), templateInstructions: 'Use concise titles.' };
  const projectPath = '/api/projects/' + project.id;
  const original = { ...createDefaultFinding(project.id), description: '<p>Rich <strong>text</strong></p>' };
  delete original.cvssVector;
  const another = createDefaultFinding(project.id);
  const findingPath = projectPath + '/findings/' + original.id;
  const session = await first.login();
  let { cookie } = session;
  assert.doesNotMatch(session.setCookie, /; Secure/);
  assert.equal((await first.request(projectPath, { method: 'PUT', cookie, body: project })).status, 204);
  const olderProject = { ...project };
  delete olderProject.templateInstructions;
  assert.equal((await first.request(projectPath, { method: 'PUT', cookie, body: olderProject })).status, 204);
  assert.equal((await first.request(projectPath, {
    method: 'PUT', cookie, body: { ...project, id: 'wrong' },
  })).status, 400);
  assert.equal((await first.request(findingPath, { method: 'PUT', cookie, body: original })).status, 204);
  assert.equal((await first.request(projectPath + '/findings/' + another.id, {
    method: 'PUT', cookie, body: another,
  })).status, 204);
  assert.equal((await first.request(findingPath, {
    method: 'PUT', cookie, body: { ...original, projectId: 'wrong' },
  })).status, 400);
  const key = await addKey(first.request, projectPath, cookie, 'Integration');
  await first.stop();

  const db = new Database(path);
  try {
    db.prepare(`
      INSERT INTO users (username, salt, password_hash)
      SELECT 'other', salt, password_hash FROM users WHERE username = 'admin'
    `).run();
    assert.equal(db.prepare('SELECT digest FROM mcp_keys').get().digest, digest(key));
    assert.equal(db.prepare('SELECT digest FROM sessions').get().digest, digest(cookie.split('=')[1]));
    assert.notEqual(db.prepare('SELECT password_hash FROM users').get().password_hash, admin.adminPassword);
  } finally {
    db.close();
  }

  const second = await runServer(t, {
    databasePath: path, adminUsername: undefined, adminPassword: undefined,
  });
  const { request } = second;
  ({ cookie } = await second.login());
  assert.deepEqual(await (await request('/api/session', { cookie })).json(), { username: 'admin' });
  assert.deepEqual(await (await request('/api/projects', { cookie })).json(), [project]);
  const findings = await (await request(projectPath + '/findings', { cookie })).json();
  assert.deepEqual(findings.find(({ id }) => id === original.id), original);
  assert.equal(findings.length, 2);
  const [keyInfo] = await (await request(projectPath + '/keys', { cookie })).json();
  assert.deepEqual(Object.keys(keyInfo).sort(), ['createdAt', 'id', 'name']);
  assert.equal(keyInfo.name, 'Integration');
  assert.ok(Date.parse(keyInfo.createdAt));

  const other = (await second.login('other')).cookie;
  assert.deepEqual(await (await request('/api/projects', { cookie: other })).json(), []);
  assert.equal((await request(projectPath + '/findings', { cookie: other })).status, 404);
  assert.equal((await request(projectPath + '/keys', { cookie: other })).status, 404);
  assert.equal((await request(projectPath, { method: 'DELETE', cookie: other })).status, 204);
  assert.equal((await request(projectPath, {
    method: 'PUT', cookie: other, body: { ...project, name: 'Other owner' },
  })).status, 204);
  assert.deepEqual(await (await request(projectPath + '/findings', { cookie: other })).json(), []);
  assert.deepEqual(await (await request(projectPath + '/keys', { cookie: other })).json(), []);
  assert.equal((await request(projectPath + '/keys/' + keyInfo.id, { method: 'DELETE', cookie: other })).status, 204);
  assert.deepEqual(await (await request(projectPath + '/keys', { cookie })).json(), [keyInfo]);
  assert.deepEqual(await (await request('/api/projects', { cookie })).json(), [project]);

  const updated = { ...original, title: 'Updated title' };
  assert.equal((await request(findingPath, { method: 'PUT', cookie, body: updated })).status, 204);
  assert.ok((await (await request(projectPath + '/findings', { cookie })).json())
    .some(({ title }) => title === updated.title));
  assert.equal((await request(findingPath, { method: 'DELETE', cookie })).status, 204);
  assert.deepEqual(await (await request(projectPath + '/findings', { cookie })).json(), [another]);
  assert.equal((await request(projectPath, { method: 'DELETE', cookie })).status, 204);
  assert.equal((await request(projectPath + '/findings', { cookie })).status, 404);
  assert.equal((await request('/mcp', { headers: { Authorization: `Bearer ${key}` } })).status, 401);
});

test('bootstrap credentials are required for a fresh database and never overwrite an existing account', async (t) => {
  assert.throws(() => createApp({ databasePath: ':memory:' }), /initialize an empty database/);
  for (const adminPassword of ['short', '               ', 'adminadminadmin', 'replace-with-a-strong-password', '🌱'.repeat(8)]) {
    assert.throws(() => createApp({ databasePath: ':memory:', ...admin, adminPassword }), /ADMIN_PASSWORD must be at least 15/);
  }
  assert.throws(() => createApp({
    databasePath: ':memory:', adminUsername: 'same as password', adminPassword: 'Same as password',
  }), /ADMIN_PASSWORD must be at least 15/);
  const path = await databasePath(t);
  const first = await runServer(t, { databasePath: path });
  await first.stop();

  const db = new Database(path);
  const legacyPassword = 'old password';
  try {
    const { salt } = db.prepare('SELECT salt FROM users').get();
    db.prepare('UPDATE users SET password_hash = ?').run(scryptSync(legacyPassword, salt, 64).toString('hex'));
  } finally {
    db.close();
  }
  const second = await runServer(t, { databasePath: path, adminPassword: 'replacement' });
  await second.login(admin.adminUsername, legacyPassword);
  assert.equal((await second.request('/api/login', {
    method: 'POST', body: { username: admin.adminUsername, password: 'replacement' },
  })).status, 401);
});

test('MCP only discovers templates and appends escaped findings to the bearer key project', async (t) => {
  const path = await databasePath(t);
  const first = await runServer(t, { databasePath: path });
  const { request, login, origin } = first;
  const { cookie } = await login();
  const project = { ...createDefaultProject('Target'), templateInstructions: 'Use plain-language titles.' };
  const other = createDefaultProject('Separate project');
  const projectPath = '/api/projects/' + project.id;
  const otherPath = '/api/projects/' + other.id;
  for (const record of [project, other]) {
    assert.equal((await request('/api/projects/' + record.id, { method: 'PUT', cookie, body: record })).status, 204);
  }
  const key = await addKey(request, projectPath, cookie, 'Operator');
  const replacement = await addKey(request, projectPath, cookie, 'Replacement');
  const otherKey = await addKey(request, otherPath, cookie, 'Other project');
  assert.equal((await request('/mcp', { cookie })).status, 401);
  assert.equal((await request('/api/projects', { headers: { Authorization: `Bearer ${key}` } })).status, 401);
  assert.equal((await request('/mcp', {
    headers: { Authorization: `Bearer ${key}`, Origin: 'https://unrelated.example' },
  })).status, 403);

  const legacy = await connectMcp(t, origin, key);
  const modern = await connectMcp(t, origin, replacement, { pin: '2026-07-28' });
  const otherClient = await connectMcp(t, origin, otherKey);
  assert.deepEqual((await modern.listTools()).tools.map(({ name }) => name).sort(),
    ['append_finding', 'get_template', 'list_templates']);
  for (const client of [legacy, modern]) {
    const guidance = await client.callTool({ name: 'list_templates', arguments: {} });
    assert.equal(guidance.structuredContent.templateInstructions, project.templateInstructions);
    assert.deepEqual(guidance.structuredContent.templates, []);
    assert.match(guidance.structuredContent.reportFormat, /Description.*\nEvidence.*\nImpact.*\nRemediation/);
    assert.match(guidance.content[0].text, /^Project guidance\nUse plain-language titles\.\n\nDefault finding format/);
  }
  assert.equal((await otherClient.callTool({ name: 'list_templates', arguments: {} }))
    .structuredContent.templateInstructions, '');

  const catalog = (await legacy.callTool({ name: 'list_templates', arguments: { query: '  INJECTION ', limit: 1 } }))
    .structuredContent;
  const { id: templateId, title, category, severity, cwe, tags } = ALL_TEMPLATES.find((t) => t.category === 'Injection');
  assert.deepEqual(catalog, {
    templates: [{ id: templateId, title, category, severity }], catalogAvailable: true, hasMore: true,
  });
  const detail = await modern.callTool({ name: 'get_template', arguments: { id: templateId } });
  assert.deepEqual(detail.structuredContent, { id: templateId, category, tags, defaults: { title, severity, cwe } });
  const noMatch = await legacy.callTool({ name: 'list_templates', arguments: { query: 'missing template id xyzz' } });
  assert.deepEqual(noMatch.structuredContent, { templates: [], catalogAvailable: true, hasMore: false });
  assert.equal((await legacy.callTool({ name: 'list_templates', arguments: { query: 'Injection', limit: 21 } })).isError, true);
  assert.equal((await legacy.callTool({ name: 'get_template', arguments: { id: 'missing-template' } })).isError, true);

  const fields = ['description', 'poc', 'requestResponse', 'impact', 'remediation', 'notes', 'references'];
  const text = '<b>literal</b> & "quoted"\nnext';
  const args = {
    idempotencyKey: 'finding-1',
    title: 'Example <report>',
    ...Object.fromEntries(fields.map((field) => [field, text])),
    description: `${text}\r\n \r\nSecond paragraph`,
    requestResponse: `  ${text}`,
  };
  const append = (client, arguments_) => client.callTool({ name: 'append_finding', arguments: arguments_ });
  const [one, two] = (await Promise.all([append(legacy, args), append(modern, args)]))
    .map((result) => result.structuredContent);
  assert.equal(one.findingId, two.findingId);
  assert.notEqual(one.created, two.created);
  assert.equal((await append(legacy, { ...args, title: 'Different content' })).isError, true);
  assert.equal((await append(legacy, { ...args, projectId: other.id })).isError, true);

  const [saved] = await (await request(projectPath + '/findings', { cookie })).json();
  assert.equal(saved.title, args.title);
  assert.equal(saved.projectId, project.id);
  assert.equal(saved.id, one.findingId);
  assert.equal(saved.status, 'Open');
  assert.equal(saved.severity, 'Medium');
  for (const field of fields) {
    const escaped = '&lt;b&gt;literal&lt;/b&gt; &amp; &quot;quoted&quot;';
    if (field === 'description') {
      assert.equal(saved[field], `<p>${escaped}<br>next</p><p>Second paragraph</p>`);
    } else if (field === 'requestResponse') {
      assert.equal(saved[field], `<pre><code>  ${escaped}\nnext</code></pre>`);
    } else {
      assert.equal(saved[field], `<p>${escaped}<br>next</p>`);
    }
  }
  assert.deepEqual(await (await request(otherPath + '/findings', { cookie })).json(), []);
  const isolated = (await append(otherClient, args)).structuredContent;
  assert.equal(isolated.created, true);
  assert.notEqual(isolated.findingId, saved.id);

  const keys = await (await request(projectPath + '/keys', { cookie })).json();
  const { id } = keys.find(({ name }) => name === 'Operator');
  assert.equal((await request(projectPath + '/keys/' + id, { method: 'DELETE', cookie })).status, 204);
  assert.equal((await request('/mcp', { headers: { Authorization: `Bearer ${key}` } })).status, 401);
  assert.equal((await request(projectPath + '/findings/' + saved.id, { method: 'DELETE', cookie })).status, 204);
  await first.stop();

  const second = await runServer(t, { databasePath: path });
  const restarted = await connectMcp(t, second.origin, replacement);
  assert.deepEqual((await append(restarted, args)).structuredContent, { created: false, findingId: saved.id });
  const newSession = await second.login();
  assert.deepEqual(await (await second.request(projectPath + '/findings', { cookie: newSession.cookie })).json(), []);
});
