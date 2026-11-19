import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { test } from 'node:test';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import express from 'express';
import { createDefaultFinding } from '../../src/types/index.ts';
import { createMcpEndpoint } from '../mcp.js';
import { openStore } from '../store.js';

async function reportTools(t, { local = true } = {}) {
  const store = openStore(':memory:', { local: true });
  const { statements, workspaceOwnerId: ownerId } = store;
  const keys = new Map();
  // The endpoint receives AuthInfo from the app. Keep its claims independent from
  // the current key lookup so these tests can exercise revocation after auth.
  if (!local) statements.mcpProject = { get: (digest) => keys.get(digest) };
  const endpoint = createMcpEndpoint(store, { local });
  const app = express();
  app.all('/mcp', (req, _res, next) => {
    if (!local) {
      const keyDigest = req.get('x-test-key');
      req.auth = { token: keyDigest, clientId: keyDigest, scopes: [], extra: {
        keyDigest, access: req.get('x-test-access'),
      } };
    }
    next();
  }, endpoint.handle);
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    await endpoint.close();
    await new Promise((resolve) => server.close(resolve));
    store.close();
  });

  async function connect({ key, access } = {}) {
    const client = new Client({ name: 'mcp-report-tests', version: '1.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
      requestInit: { headers: key ? { 'x-test-key': key, 'x-test-access': access } : {} },
    });
    t.after(() => client.close());
    await client.connect(transport);
    return {
      tools: async () => (await client.listTools()).tools.map(({ name }) => name).sort(),
      call: (name, args = {}) => client.callTool({ name, arguments: args }),
    };
  }

  function project(id, guidance = null) {
    statements.putProject.run(ownerId, id, JSON.stringify({ id, name: id }), guidance);
    return { id, owner_id: ownerId, template_instructions: guidance };
  }

  function seedFinding(projectId, fields) {
    const finding = { ...createDefaultFinding(projectId), ...fields };
    statements.insertFinding.run(ownerId, projectId, finding.id, JSON.stringify(finding));
    return finding;
  }

  return { project, keys, connect, seedFinding, statements, ownerId };
}

function data(response) {
  assert.notEqual(response.isError, true, response.content[0]?.text);
  return response.structuredContent;
}

function toolError(response, message) {
  assert.equal(response.isError, true);
  assert.equal(response.structuredContent, undefined);
  assert.match(response.content[0].text, message);
}

test('list_projects counts findings and list_findings pages compact results with scoped filters', async (t) => {
  const { connect, project, seedFinding } = await reportTools(t);
  const { call, tools } = await connect();
  assert.deepEqual(await tools(), [
    'append_finding', 'append_findings', 'get_finding', 'get_template',
    'list_findings', 'list_projects', 'list_templates', 'update_finding',
  ]);
  assert.deepEqual(data(await call('list_projects')), { projects: [] });
  toolError(await call('list_findings'), /No projects/);

  project('primary');
  project('other');
  const common = { severity: 'High', createdAt: '2026-01-01', description: '<p>Private report body</p>' };
  seedFinding('primary', { ...common, id: 'a', title: 'Unencrypted backups', status: 'Open' });
  seedFinding('primary', { ...common, id: 'b', title: 'Unencrypted exports', status: 'New', confidence: 'low' });
  seedFinding('primary', { ...common, id: 'c', title: 'Missing audit logs', severity: 'Low', status: 'New' });
  seedFinding('other', { ...common, id: 'a', title: 'Unencrypted archive', status: 'New' });

  assert.deepEqual(data(await call('list_projects')), { projects: [
    { id: 'other', name: 'other', findingCount: 1 },
    { id: 'primary', name: 'primary', findingCount: 3 },
  ] });
  toolError(await call('list_findings'), /supply projectId/);
  const filter = { projectId: 'primary', query: 'UNENCRYPTED', severity: 'High', limit: 1 };
  const first = data(await call('list_findings', filter));
  assert.deepEqual(first, {
    findings: [{ id: 'a', title: 'Unencrypted backups', status: 'Open', severity: 'High', createdAt: common.createdAt }],
    hasMore: true, nextOffset: 1,
  });
  const next = data(await call('list_findings', { ...filter, offset: first.nextOffset }));
  assert.equal(next.hasMore, false);
  assert.deepEqual(next.findings.map(({ id, confidence }) => [id, confidence]), [['b', 'low']]);
  for (const [status, id] of [['Open', 'a'], ['New', 'b']]) {
    const page = data(await call('list_findings', { ...filter, status }));
    assert.deepEqual(page.findings.map((finding) => finding.id), [id]);
    assert.equal(page.hasMore, false);
  }
  const nonMatches = { findings: [], hasMore: false };
  assert.deepEqual(data(await call('list_findings', { ...filter, query: 'Private report body' })), nonMatches);
  assert.deepEqual(data(await call('list_findings', { ...filter, query: '%' })), nonMatches);
  toolError(await call('list_findings', { ...filter, offset: -1 }), /Invalid arguments/);
});

test('catalog browsing has separate guidance, category pages, and plain template detail', async (t) => {
  const { connect, project } = await reportTools(t);
  project('primary');
  project('guided', 'Use concise titles.');
  const { call } = await connect();
  const guidance = await call('list_templates', { projectId: 'primary' });
  assert.equal(data(guidance).hasGuidance, false);
  assert.ok(data(guidance).templates.length > 0);
  assert.match(guidance.content[0].text, /No project-specific instructions/);
  assert.equal(data(await call('list_templates', { projectId: 'guided' })).templateInstructions, 'Use concise titles.');

  const browse = { projectId: 'primary', limit: 1 };
  const first = data(await call('list_templates', browse));
  const second = data(await call('list_templates', { ...browse, offset: first.nextOffset }));
  assert.equal(first.catalogAvailable, true);
  assert.equal(first.hasMore, true);
  assert.equal(first.templateInstructions, undefined);
  assert.notEqual(first.templates[0].id, second.templates[0].id);
  const category = { ...browse, category: 'authentication' };
  const page = data(await call('list_templates', category));
  assert.equal(page.templates[0].category, 'Authentication');
  assert.equal(data(await call('list_templates', { ...category, offset: page.nextOffset })).templates[0].category,
    'Authentication');
  const { id, title, severity } = page.templates[0];
  const template = data(await call('get_template', { projectId: 'primary', id }));
  assert.equal(template.defaults.title, title);
  assert.equal(template.defaults.severity, severity);
  assert.ok(template.remediation_hint.length > 0);
  assert.doesNotMatch(template.remediation_hint, /<\/?(?:p|li|ol|strong)\b/i);
  assert.ok(template.references.length > 0);
  assert.ok(template.references.every((reference) => reference.startsWith('https://')));
  toolError(await call('get_template', { projectId: 'primary', id: 'unknown' }), /Unknown template ID/);

  const submission = { templateId: id, idempotencyKey: 'inherit', projectId: 'primary' };
  const { findingId: inheritedId } = data(await call('append_finding', submission));
  const selection = { id: inheritedId, projectId: 'primary' };
  const inherited = data(await call('get_finding', selection)).finding;
  for (const [field, value] of Object.entries(template.defaults)) assert.equal(inherited[field], value);
  assert.equal(inherited.templateId, id);
  assert.equal(inherited.category, template.category);
  assert.deepEqual(inherited.tags, template.tags);
  assert.notEqual(inherited.remediation, '');
  assert.ok(template.references.every((reference) => inherited.references.includes(reference)));
  assert.equal(inherited.description, '');
  assert.equal(inherited.url, '');
  assert.equal(inherited.status, 'New');
  data(await call('update_finding', { ...selection, patch: { status: 'Duplicate', remediation: '' } }));
  assert.deepEqual(data(await call('append_finding', submission)), { findingId: inheritedId, created: false });
  assert.equal(data(await call('get_finding', selection)).finding.remediation, '');

  const input = {
    templateId: id, idempotencyKey: 'explicit', title: 'My title', severity: 'Info',
    cwe: '', category: 'Custom', tags: [], remediation: '', references: '',
  };
  const explicitId = data(await call('append_finding', { ...input, projectId: 'primary' })).findingId;
  const explicit = data(await call('get_finding', { id: explicitId, projectId: 'primary' })).finding;
  for (const [field, value] of Object.entries(input)) {
    if (field !== 'idempotencyKey') assert.deepEqual(explicit[field], value);
  }
});

test('update_finding validates a strict patch, preserves other fields, and stores evidence as metadata', async (t) => {
  const { connect, project, seedFinding } = await reportTools(t);
  project('primary');
  project('other');
  const original = seedFinding('primary', {
    id: 'legacy', title: 'Original title', status: 'Open', description: '<p>Original</p>',
  });
  const { call } = await connect();
  const get = async () => data(await call('get_finding', { projectId: 'primary', id: original.id })).finding;
  const update = (patch) => call('update_finding', { projectId: 'primary', id: original.id, patch });
  const patch = {
    status: 'Verified', confidence: 'high', triageNotes: 'Keep <this> as plain text',
    evidence: ['evidence/local image.png', 'https://storage.example/report.txt', 'file:///tmp/report.txt'],
    targets: [{ url: '/api/items', method: 'HEAD', parameter: 'version', host: 'app.example', port: '443' }],
    description: '<b>Example</b>\nnext',
  };
  assert.deepEqual(data(await update(patch)), { findingId: original.id, updated: true });
  const expected = { ...original, ...patch, description: '<p>&lt;b&gt;Example&lt;/b&gt;<br>next</p>' };
  assert.deepEqual(await get(), expected);
  for (const malformed of [
    {}, { id: 'forged' }, { projectId: 'other' }, { createdAt: 'today' }, { status: 'Resolved' },
    { confidence: 'HIGH' }, { description: null }, { triageNotes: ['notes'] },
    { evidence: [{ path: 'record.txt' }] }, { evidence: ['data:text/plain,inline'] }, { evidence: [''] },
    { targets: [{ host: 'app.example' }] }, { targets: [{ url: '/api', payload: 'extra' }] },
  ]) {
    toolError(await update(malformed), /Invalid arguments/);
  }
  toolError(await update({ templateId: 'unknown' }), /Unknown template ID/);
  assert.deepEqual(await get(), expected);
  await update({ evidence: [], targets: [], description: '', triageNotes: '' });
  assert.deepEqual(await get(), { ...expected, evidence: [], targets: [], description: '', triageNotes: '' });

  const destination = { projectId: 'other', id: original.id };
  toolError(await call('get_finding', destination), /Unknown finding ID/);
  toolError(await call('update_finding', { ...destination, patch: { status: 'Fixed' } }), /Unknown finding ID/);
});

test('batch reports per-item errors and uses the historical append digest before and after edits', async (t) => {
  const { connect, project, seedFinding, statements, ownerId } = await reportTools(t);
  project('primary');
  seedFinding('primary', { id: 'historical', title: 'Sample', status: 'Open' });
  const historicalJson = JSON.stringify({
    title: 'Sample', severity: 'Medium', description: '', poc: '', requestResponse: '', impact: '',
    remediation: '', notes: '', references: '', url: '', method: '', parameter: '', affectedHost: '',
    port: '', cve: '', cwe: '', cvss: '', cvssVector: '',
  });
  statements.insertAppend.run(ownerId, 'primary', 'old-key',
    createHash('sha256').update(historicalJson).digest('hex'), 'historical');
  const { call } = await connect();
  const retry = { title: ' Sample ', idempotencyKey: ' old-key ', severity: 'Medium' };
  const historical = { findingId: 'historical', created: false };
  assert.deepEqual(data(await call('append_finding', retry)), historical);

  const item = { idempotencyKey: 'new-key', title: 'New record', targets: [{ url: '/report', method: 'GET' }] };
  const batch = { findings: [
    retry, item, null, 42, { idempotencyKey: 'bad-fields', title: 'Wrong', createdAt: 'now' },
    { idempotencyKey: 'bad-template', templateId: 'missing' }, { ...item, title: 'Conflict' },
    { ...item, targets: [{ method: 'GET', url: '/report' }] },
  ] };
  const { results } = data(await call('append_findings', batch));
  assert.deepEqual(results.map(({ index }) => index), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(results[0], { index: 0, ...historical });
  const { findingId } = results[1];
  assert.equal(results[1].created, true);
  assert.ok(findingId);
  for (const index of [2, 3, 4]) assert.ok(results[index].error);
  assert.match(results[5].error, /Unknown template ID/);
  assert.match(results[6].error, /idempotencyKey/);
  assert.deepEqual(results[7], { index: 7, findingId, created: false });

  for (const id of ['historical', findingId]) {
    data(await call('update_finding', { id, patch: { title: 'Edited', status: 'Fixed' } }));
  }
  assert.deepEqual(data(await call('append_finding', retry)), historical);
  assert.deepEqual(data(await call('append_finding', item)), { findingId, created: false });
  assert.equal(data(await call('get_finding', { id: findingId })).finding.title, 'Edited');
  assert.equal(data(await call('list_findings')).findings.length, 2);
  toolError(await call('append_findings', { findings: [] }), /Invalid arguments/);
  toolError(await call('append_finding', { idempotencyKey: 'missing-title' }), /Provide a title or a templateId/);
});

test('organization manages only the key project and rechecks live access on every call', async (t) => {
  const { connect, project, keys, seedFinding } = await reportTools(t, { local: false });
  keys.set('manager', { ...project('primary'), access: 'manage' });
  keys.set('writer', { ...project('other'), access: 'append' });
  seedFinding('primary', { id: 'here', title: 'Visible' });
  seedFinding('other', { id: 'elsewhere', title: 'Private' });
  const writer = await connect({ key: 'writer', access: 'append' });
  const manager = await connect({ key: 'manager', access: 'manage' });
  assert.deepEqual(await writer.tools(), ['append_finding', 'append_findings', 'get_template', 'list_templates']);
  await assert.rejects(writer.call('list_findings'), /not found/);
  assert.deepEqual(await manager.tools(), [
    'append_finding', 'append_findings', 'get_finding', 'get_template', 'list_findings', 'list_templates', 'update_finding',
  ]);
  assert.deepEqual(data(await manager.call('list_findings')).findings.map(({ id }) => id), ['here']);
  toolError(await manager.call('list_findings', { projectId: 'other' }), /Invalid arguments/);
  toolError(await manager.call('get_finding', { id: 'elsewhere' }), /Unknown finding ID/);
  toolError(await manager.call('update_finding', { id: 'elsewhere', patch: { status: 'Fixed' } }), /Unknown finding ID/);
  data(await manager.call('update_finding', { id: 'here', patch: { status: 'Fixed' } }));

  keys.get('manager').access = 'append';
  toolError(await manager.call('list_findings'), /requires a manage project key/);
  keys.delete('manager');
  toolError(await manager.call('list_findings'), /revoked project key/);
  toolError(await manager.call('get_finding', { id: 'here' }), /revoked project key/);
  toolError(await manager.call('update_finding', { id: 'here', patch: { status: 'New' } }), /revoked project key/);
});
