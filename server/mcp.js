import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { ALL_TEMPLATES } from '../src/data/templates/index.ts';
import { createDefaultFinding } from '../src/types/index.ts';
import { severity } from './schemas.js';
import { digest } from './store.js';

const templates = ALL_TEMPLATES.map(({ id, title, category, severity }) => ({ id, title, category, severity }));
const contentFields = ['description', 'poc', 'requestResponse', 'impact', 'remediation', 'notes', 'references'];
const text = z.string().max(24_000).default('');
const metadata = z.string().max(2_048).default('');
const appendInput = z.strictObject({
  idempotencyKey: z.string().trim().min(1).max(200),
  title: z.string().trim().min(1).max(240),
  severity: severity.default('Medium'),
  description: text,
  poc: text,
  requestResponse: text,
  impact: text,
  remediation: text,
  notes: text,
  references: text,
  url: metadata,
  method: metadata,
  parameter: metadata,
  affectedHost: metadata,
  port: metadata,
  cve: metadata,
  cwe: metadata,
  cvss: metadata,
  cvssVector: metadata,
});

const htmlEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function renderText(value) {
  if (!value) return '';
  const escaped = value.replace(/[&<>"']/g, (char) => htmlEntities[char]);
  return `<p>${escaped.replace(/\r\n?|\n/g, '<br>')}</p>`;
}

function result(data) {
  return { structuredContent: data, content: [{ type: 'text', text: JSON.stringify(data) }] };
}

function failure(text) {
  return { isError: true, content: [{ type: 'text', text }] };
}

export function createMcpEndpoint(store) {
  const maxRequestBodySize = 256 * 1024;
  const handler = createMcpHandler(({ authInfo }) => {
    const { keyDigest } = authInfo.extra;
    const server = new McpServer({ name: 'peng', version: '1.0.0' });

    server.registerTool('list_templates', {
      description: 'List compact finding template metadata and the project’s template instructions.',
      inputSchema: z.strictObject({}),
      outputSchema: z.object({
        templateInstructions: z.string(),
        templates: z.array(z.object({ id: z.string(), title: z.string(), category: z.string(), severity })),
      }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    }, () => {
      const project = store.statements.mcpProject.get(keyDigest);
      if (!project) return failure('Invalid or revoked project key');
      return result({ templateInstructions: project.template_instructions ?? '', templates });
    });

    server.registerTool('append_finding', {
      description: 'Append a new finding to this key’s project. Submit plain text and reuse the same idempotencyKey when retrying.',
      inputSchema: appendInput,
      outputSchema: z.object({ findingId: z.string(), created: z.boolean() }),
      annotations: { destructiveHint: false, idempotentHint: true, openWorldHint: false },
    }, ({ idempotencyKey, ...values }) => {
      const outcome = store.appendFinding(keyDigest, idempotencyKey, digest(JSON.stringify(values)), (projectId) => {
        const finding = { ...createDefaultFinding(projectId), ...values };
        for (const field of contentFields) finding[field] = renderText(finding[field]);
        return finding;
      });
      return outcome.error ? failure(outcome.error) : result(outcome);
    });

    return server;
  }, { maxRequestBodySize, maxSubscriptions: 0 });

  return {
    handle: toNodeHandler(handler, { maxRequestBodySize }),
    close: () => handler.close(),
  };
}
