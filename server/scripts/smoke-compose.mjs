// Run against the disposable Compose stack started by CI.
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createDefaultProject } from '../../src/types/index.ts';

const origin = new URL(process.env.SMOKE_URL).origin;
const mode = process.env.DEPLOY_MODE ?? 'organization';
assert.ok(['local', 'organization'].includes(mode), 'Invalid DEPLOY_MODE');
const local = mode === 'local';
const project = { ...createDefaultProject('Compose smoke'), templateInstructions: 'Use concise titles.' };
const other = createDefaultProject('Separate smoke project');
const path = '/api/projects/' + project.id;
const otherPath = '/api/projects/' + other.id;
let cookie;
async function request(path, method = 'GET', body, status = 200, requestOrigin = origin) {
  const response = await fetch(origin + path, {
    method,
    headers: { Origin: requestOrigin, 'Content-Type': 'application/json', ...(cookie && { Cookie: cookie }) },
    body: JSON.stringify(body),
  });
  assert.equal(response.status, status, method + ' ' + path + ' returned ' + response.status);
  return response;
}

assert.deepEqual(await (await request('/api/config')).json(), { mode });
if (local) {
  const session = await request('/api/session');
  assert.deepEqual(await session.json(), { mode: 'local' });
  assert.equal(session.headers.get('set-cookie'), null);
  await request('/api/login', 'POST', {}, 404);
  await request('/api/logout', 'POST', undefined, 404);
} else {
  await request('/api/session', 'GET', undefined, 401);
  await request('/api/projects', 'GET', undefined, 401);
  const unauthenticated = await request('/mcp', 'GET', undefined, 401);
  assert.match(unauthenticated.headers.get('www-authenticate'), /^Bearer\b/);
  const username = process.env.ADMIN_USERNAME;
  const login = await request('/api/login', 'POST', { username, password: process.env.ADMIN_PASSWORD });
  cookie = login.headers.get('set-cookie').split(';')[0];
  assert.deepEqual(await (await request('/api/session')).json(), { username, mode });
}

const client = new Client({ name: 'compose-smoke', version: '1' });
try {
  await request(path, 'PUT', project, 403, 'http://untrusted.example');
  await request(path, 'PUT', project, 204);
  await request(otherPath, 'PUT', other, 204);
  const headers = {};
  if (local) {
    await request(path + '/keys', 'GET', undefined, 404);
    await request(path + '/keys', 'POST', { name: 'Smoke' }, 404);
    await request(path + '/keys/unused', 'DELETE', undefined, 404);
    await request('/mcp', 'GET', undefined, 403, 'http://untrusted.example');
  } else {
    const { key } = await (await request(path + '/keys', 'POST', { name: 'Smoke' }, 201)).json();
    headers.Authorization = 'Bearer ' + key;
  }
  await client.connect(new StreamableHTTPClientTransport(new URL('/mcp', origin), { requestInit: { headers } }));
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(tool => tool.name).sort(), [
    'append_finding', 'get_template', ...(local ? ['list_projects'] : []), 'list_templates',
  ]);
  if (local) {
    const { structuredContent: { projects } } = await client.callTool({ name: 'list_projects', arguments: {} });
    assert.deepEqual(new Map(projects.map(({ id, name }) => [id, name])),
      new Map([[project.id, project.name], [other.id, other.name]]));
    assert.equal((await client.callTool({ name: 'list_templates', arguments: {} })).isError, true);
    assert.equal((await client.callTool({ name: 'list_templates', arguments: { projectId: 'unknown' } })).isError, true);
  }
  const selection = local ? { projectId: project.id } : {};
  const guidance = await client.callTool({ name: 'list_templates', arguments: selection });
  assert.equal(guidance.structuredContent.templateInstructions, project.templateInstructions);
  assert.equal(guidance.structuredContent.catalogAvailable, true);
  assert.deepEqual(guidance.structuredContent.templates, []);
  const search = await client.callTool({ name: 'list_templates', arguments: { ...selection, query: 'network', limit: 1 } });
  const [template] = search.structuredContent.templates;
  const detail = await client.callTool({ name: 'get_template', arguments: { ...selection, id: template.id } });
  assert.equal(detail.structuredContent.defaults.title, template.title);
  const submission = { name: 'append_finding', arguments: { ...selection, title: 'Smoke finding', idempotencyKey: 'smoke' } };
  assert.equal((await client.callTool(submission)).structuredContent.created, true);
  assert.equal((await client.callTool(submission)).structuredContent.created, false);
  const findings = await (await request(path + '/findings')).json();
  assert.deepEqual(findings.map(f => f.title), ['Smoke finding']);
  assert.deepEqual(await (await request(otherPath + '/findings')).json(), []);
  if (!local) {
    const [issued] = await (await request(path + '/keys')).json();
    await request(path + '/keys/' + issued.id, 'DELETE', undefined, 204);
    assert.equal((await fetch(origin + '/mcp', { headers })).status, 401);
  }
} finally {
  await client.close();
  await request(path, 'DELETE', undefined, 204);
  await request(otherPath, 'DELETE', undefined, 204);
  if (!local) await request('/api/logout', 'POST', undefined, 204);
}
