import { ALL_TEMPLATES as templates } from '../src/data/templates/index.ts';
import { createDefaultFinding } from '../src/types/index.ts';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { severity } from './schemas.js';
import { digest } from './store.js';

const templatesById = new Map(templates.map((template) => [template.id, template]));
const templateSummary = z.object({ id: z.string(), title: z.string(), category: z.string(), severity });
const readOnly = { readOnlyHint: true, openWorldHint: false };
const guidanceFirst = 'Call list_templates with {} first to read project guidance and the default finding format. Search for a template only if it helps with the report.';
const reportFormat = [
  'Title and severity — Name the finding and rate the observed risk.',
  'Description — Summarize what was observed and identify the affected asset.',
  'Evidence — Record verified observations in poc. Put redacted request and response samples in requestResponse.',
  'Impact — Explain who or what is affected and under what conditions.',
  'Remediation — Give concrete fixes and a way to verify them.',
  'References — Put relevant links on separate lines. Omit fields that do not apply.',
].join('\n');
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

function renderText(value, field) {
  if (!value.trim()) return '';
  const escaped = value.replace(/\r\n?/g, '\n').replace(/[&<>"']/g, (char) => htmlEntities[char]);
  if (field === 'requestResponse') return `<pre><code>${escaped}</code></pre>`;
  return escaped.trim().split(/\n(?:[^\S\n]*\n)+/)
    .map((paragraph) => `<p>${paragraph.replaceAll('\n', '<br>')}</p>`).join('');
}

function result(data, text = JSON.stringify(data)) {
  return { structuredContent: data, content: [{ type: 'text', text }] };
}

function failure(text) {
  return { isError: true, content: [{ type: 'text', text }] };
}

export function createMcpEndpoint(store) {
  const maxRequestBodySize = 256 * 1024;
  const handler = createMcpHandler(({ authInfo }) => {
    const { keyDigest } = authInfo.extra;
    const server = new McpServer({ name: 'peng', version: '1.0.0' }, { instructions: guidanceFirst });

    server.registerTool('list_templates', {
      description: 'Start here with {} for project instructions and the default finding format. Supply a query for an optional, bounded search of template summaries.',
      inputSchema: z.strictObject({
        query: z.string().trim().min(1).max(120).optional(),
        limit: z.number().int().min(1).max(20).default(8),
      }),
      outputSchema: z.object({
        templateInstructions: z.string().optional(),
        reportFormat: z.string().optional(),
        templates: z.array(templateSummary),
        catalogAvailable: z.boolean(),
        hasMore: z.boolean().optional(),
      }),
      annotations: readOnly,
    }, ({ query, limit }) => {
      const project = store.statements.mcpProject.get(keyDigest);
      if (!project) return failure('Invalid or revoked project key');
      const catalogAvailable = templates.length > 0;
      if (query === undefined) {
        const templateInstructions = project.template_instructions ?? '';
        return result({ templateInstructions, reportFormat, templates: [], catalogAvailable },
          `Project guidance\n${templateInstructions || 'No project-specific instructions.'}\n\nDefault finding format\n${reportFormat}`);
      }

      const terms = query.toLowerCase().split(/\s+/);
      const matches = [];
      for (const { id, title, category, severity, cwe, tags } of templates) {
        const searchable = [id, title, category, severity, cwe, ...tags].join(' ').toLowerCase();
        if (!terms.every((term) => searchable.includes(term))) continue;
        matches.push({ id, title, category, severity });
        if (matches.length > limit) break;
      }
      return result({ templates: matches.slice(0, limit), catalogAvailable, hasMore: matches.length > limit });
    });

    server.registerTool('get_template', {
      description: 'Get suggested title, severity, and CWE defaults for a template ID from list_templates. Adapt them to the verified finding.',
      inputSchema: z.strictObject({ id: z.string().trim().min(1).max(120) }),
      outputSchema: z.object({
        id: z.string(), category: z.string(), tags: z.array(z.string()),
        defaults: z.object({ title: z.string(), severity, cwe: z.string().optional() }),
      }),
      annotations: readOnly,
    }, ({ id }) => {
      if (!store.statements.mcpProject.get(keyDigest)) return failure('Invalid or revoked project key');
      if (!templates.length) return failure('Template catalog unavailable. Use the default finding format from list_templates.');
      const template = templatesById.get(id);
      if (!template) return failure('Unknown template ID');
      const { title, severity, category, cwe, tags } = template;
      return result({ id, category, tags, defaults: { title, severity, ...(cwe ? { cwe } : {}) } });
    });

    server.registerTool('append_finding', {
      description: 'Append a new finding to this key’s project. Read project guidance first via list_templates with {}. Submit plain text, separate paragraphs with blank lines, and reuse the same idempotencyKey when retrying.',
      inputSchema: appendInput,
      outputSchema: z.object({ findingId: z.string(), created: z.boolean() }),
      annotations: { destructiveHint: false, idempotentHint: true, openWorldHint: false },
    }, ({ idempotencyKey, ...values }) => {
      const outcome = store.appendFinding(keyDigest, idempotencyKey, digest(JSON.stringify(values)), (projectId) => {
        const finding = { ...createDefaultFinding(projectId), ...values };
        for (const field of contentFields) finding[field] = renderText(finding[field], field);
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
