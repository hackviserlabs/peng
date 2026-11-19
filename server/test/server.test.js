import assert from 'node:assert/strict';
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
import { digest } from '../store.js';

const admin = { adminUsername: 'admin', adminPassword: 'test password' };

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

  async function login(username = admin.adminUsername) {
    const response = await request('/api/login', {
      method: 'POST',
      body: { username, password: admin.adminPassword },
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
  assert.match(logout.headers.get('set-cookie'), /^peng_session=;/);
  assert.equal((await request('/api/session', { cookie: renewedCookie })).status, 401);
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
  const { cookie, setCookie } = await first.login();
  assert.doesNotMatch(setCookie, /; Secure/);
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
  const path = await databasePath(t);
  const first = await runServer(t, { databasePath: path });
  await first.stop();
  const second = await runServer(t, { databasePath: path, adminPassword: 'replacement' });
  await second.login();
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
  assert.deepEqual((await modern.listTools()).tools.map(({ name }) => name).sort(), ['append_finding', 'list_templates']);
  const catalog = (await legacy.callTool({ name: 'list_templates', arguments: {} })).structuredContent;
  assert.equal(catalog.templateInstructions, project.templateInstructions);
  assert.deepEqual(catalog.templates, ALL_TEMPLATES.map(({ id, title, category, severity }) => ({
    id, title, category, severity,
  })));
  assert.equal((await otherClient.callTool({ name: 'list_templates', arguments: {} }))
    .structuredContent.templateInstructions, '');

  const fields = ['description', 'poc', 'requestResponse', 'impact', 'remediation', 'notes', 'references'];
  const text = '<b>literal</b> & "quoted"\nnext';
  const args = {
    idempotencyKey: 'finding-1',
    title: 'Example <report>',
    ...Object.fromEntries(fields.map((field) => [field, text])),
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
    assert.equal(saved[field], '<p>&lt;b&gt;literal&lt;/b&gt; &amp; &quot;quoted&quot;<br>next</p>');
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
  assert.deepEqual(await (await second.request(projectPath + '/findings', { cookie })).json(), []);
});
