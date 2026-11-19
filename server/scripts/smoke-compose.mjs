// Run against the disposable Compose stack started by CI.
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createDefaultProject } from '../../src/types/index.ts';

const origin = new URL(process.env.SMOKE_URL).origin;
const project = { ...createDefaultProject('Compose smoke'), templateInstructions: 'Use concise titles.' };
const path = '/api/projects/' + project.id;
let cookie;
async function request(path, method, body) {
  const response = await fetch(origin + path, {
    method,
    headers: { Origin: origin, 'Content-Type': 'application/json', ...(cookie && { Cookie: cookie }) },
    body: JSON.stringify(body),
  });
  assert.ok(response.ok, method + ' ' + path + ' returned ' + response.status);
  return response;
}
const login = await request('/api/login', 'POST', {
  username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD,
});
cookie = login.headers.get('set-cookie').split(';')[0];
await request(path, 'PUT', project);
const client = new Client({ name: 'compose-smoke', version: '1' });
try {
  const { key } = await (await request(path + '/keys', 'POST', { name: 'Smoke' })).json();
  const headers = { Authorization: 'Bearer ' + key };
  await client.connect(new StreamableHTTPClientTransport(new URL('/mcp', origin), { requestInit: { headers } }));
  const guidance = await client.callTool({ name: 'list_templates', arguments: {} });
  assert.equal(guidance.structuredContent.templateInstructions, project.templateInstructions);
  assert.equal(guidance.structuredContent.catalogAvailable, true);
  assert.deepEqual(guidance.structuredContent.templates, []);
  const search = await client.callTool({ name: 'list_templates', arguments: { query: 'network', limit: 1 } });
  const [template] = search.structuredContent.templates;
  const detail = await client.callTool({ name: 'get_template', arguments: { id: template.id } });
  assert.equal(detail.structuredContent.defaults.title, template.title);
  const submission = { name: 'append_finding', arguments: { title: 'Smoke finding', idempotencyKey: 'smoke' } };
  assert.equal((await client.callTool(submission)).structuredContent.created, true);
  assert.equal((await client.callTool(submission)).structuredContent.created, false);
  const findings = await (await request(path + '/findings', 'GET')).json();
  assert.deepEqual(findings.map(f => f.title), ['Smoke finding']);
  const [issued] = await (await request(path + '/keys', 'GET')).json();
  await request(path + '/keys/' + issued.id, 'DELETE');
  assert.equal((await fetch(origin + '/mcp', { headers })).status, 401);
} finally {
  await client.close();
  await request(path, 'DELETE');
  await request('/api/logout', 'POST');
}
