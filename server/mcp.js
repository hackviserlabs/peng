import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { normalizeWorkspaceId, readLegacyWorkspaceLink, readWorkspacePath } from '../src/types/findingLink.ts';
import {
  appendDigest, appendInput, evidenceGuidance, findingConfidence, findingDetails, findingPatch, findingStatus,
  newFinding, renderFindingFields, templateId,
} from './mcp-findings.js';
import { catalogSummaries, templateDetails, templateFindingFields, templates, templatesById } from './mcp-templates.js';
import { id as projectIdSchema, isProjectFindingStatus, severity } from './schemas.js';

const templateSummary = z.object({ id: z.string(), title: z.string(), category: z.string(), severity });
const findingSummary = z.object({
  id: z.string(), title: z.string(), severity, status: findingStatus, createdAt: z.string(),
  confidence: findingConfidence.optional(), templateId: z.string().optional(), category: z.string().optional(),
});
const findingDetail = findingDetails.extend(findingSummary.shape);
const appendOutcome = z.object({ findingId: z.string(), created: z.boolean() });
const offsetInput = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const pageInfo = { hasMore: z.boolean(), nextOffset: offsetInput.optional() };
const queryInput = z.string().trim().min(1).max(120).optional();
const readOnly = { readOnlyHint: true, openWorldHint: false };
const appendAnnotations = { destructiveHint: false, idempotentHint: true, openWorldHint: false };
const reportFormat = [
  'Title and severity — Name the finding and rate the observed risk.',
  'Description — Summarize what was observed and identify the affected asset.',
  `Evidence — ${evidenceGuidance}`,
  'Impact — Explain who or what is affected and under what conditions.',
  'Remediation — Give concrete fixes and a way to verify them.',
  'References — Put relevant links on separate lines. Omit fields that do not apply.',
].join('\n');

function result(data, text = JSON.stringify(data)) {
  return { structuredContent: data, content: [{ type: 'text', text }] };
}

function failure(text) {
  return { isError: true, content: [{ type: 'text', text }] };
}

function pagination(hasMore, offset, limit) {
  return { hasMore, ...(hasMore ? { nextOffset: offset + limit } : {}) };
}

export function createMcpEndpoint(store, { local }) {
  const maxRequestBodySize = 256 * 1024;
  const { statements, workspaceOwnerId } = store;
  const projectInput = local ? { projectId: projectIdSchema.optional() } : {};
  const guidanceInput = local ? '{projectId, guidanceOnly: true}' : '{guidanceOnly: true}';
  const instructions = [
    ...(local ? ['Call list_projects to discover workspace projects and use the selected projectId in report tools.'] : []),
    `Call list_templates with ${guidanceInput} once per project in each reporting session to read project guidance and the default finding format.`,
    'Browse or search the catalog when a template helps with the report.',
  ].join(' ');

  const handler = createMcpHandler(({ authInfo }) => {
    const server = new McpServer({ name: 'peng', version: '1.0.0' }, { instructions });
    const keyDigest = authInfo?.extra?.keyDigest;
    const canManage = local || authInfo?.extra?.access === 'manage';

    function selectProject(projectId, manage = false) {
      if (!local) {
        const project = keyDigest && statements.mcpProject.get(keyDigest);
        if (!project) return { error: 'Invalid or revoked project key' };
        if (manage && (!canManage || project.access !== 'manage')) {
          return { error: 'This tool requires a manage project key' };
        }
        return project;
      }
      if (projectId !== undefined) {
        return statements.project.get(workspaceOwnerId, normalizeWorkspaceId(projectId)) ?? { error: 'Unknown project ID' };
      }
      const candidates = statements.projectCandidates.all(workspaceOwnerId);
      if (candidates.length === 0) return { error: 'No projects in the local workspace' };
      if (candidates.length > 1) return { error: 'Use list_projects and supply projectId to select a project' };
      return candidates[0];
    }

    if (local) {
      server.registerTool('list_projects', {
        description: 'List local workspace projects, their IDs, and their finding counts.',
        inputSchema: z.strictObject({}),
        outputSchema: z.object({
          projects: z.array(z.object({ id: z.string(), name: z.string(), findingCount: z.number().int() })),
        }),
        annotations: readOnly,
      }, () => result({ projects: statements.mcpProjects.all(workspaceOwnerId) }));
    }

    server.registerTool('list_templates', {
      description: `Use ${guidanceInput} to read project guidance and the default finding format without the catalog. By default, an unfiltered call includes the first catalog page. Use limit and offset to browse, or filter by category or query.`,
      inputSchema: z.strictObject({
        ...projectInput,
        guidanceOnly: z.boolean().optional().describe(
          'Return only project instructions and the default finding format. Catalog filters and pagination are ignored when true.',
        ),
        query: queryInput,
        category: z.string().trim().min(1).max(120).optional(),
        limit: z.number().int().min(1).max(20).optional(),
        offset: offsetInput.optional(),
      }),
      outputSchema: z.object({
        templateInstructions: z.string().optional(),
        hasGuidance: z.boolean().optional(),
        reportFormat: z.string().optional(),
        templates: z.array(templateSummary).optional(),
        catalogAvailable: z.boolean().optional(),
        hasMore: pageInfo.hasMore.optional(),
        nextOffset: pageInfo.nextOffset,
      }),
      annotations: readOnly,
    }, ({ projectId, guidanceOnly, query, category, limit, offset }) => {
      const project = selectProject(projectId);
      if (project.error) return failure(project.error);
      const templateInstructions = project.template_instructions ?? '';
      const hasGuidance = templateInstructions.trim().length > 0;
      const guidance = { templateInstructions, hasGuidance, reportFormat };
      const guidanceText = `Project guidance\n${hasGuidance ? templateInstructions : 'No project-specific instructions.'}\n\nDefault finding format\n${reportFormat}`;
      if (guidanceOnly) return result(guidance, guidanceText);

      const matches = catalogSummaries(query, category);
      const start = offset ?? 0;
      const pageSize = limit ?? 8;
      const page = {
        templates: matches.slice(start, start + pageSize),
        catalogAvailable: templates.length > 0,
        ...pagination(matches.length > start + pageSize, start, pageSize),
      };
      if (query !== undefined || category !== undefined || limit !== undefined || offset !== undefined) {
        return result(page);
      }

      return result({ ...guidance, ...page }, `${guidanceText}\n\nTemplate catalog\n${JSON.stringify(page)}`);
    });

    server.registerTool('get_template', {
      description: 'Get suggested defaults, a plain-text remediation hint, and reference URLs for a template ID from list_templates.',
      inputSchema: z.strictObject({ ...projectInput, id: templateId }),
      outputSchema: z.object({
        id: z.string(), category: z.string(), tags: z.array(z.string()),
        defaults: z.object({ title: z.string(), severity, cwe: z.string().optional() }),
        remediation_hint: z.string(), references: z.array(z.string()),
      }),
      annotations: readOnly,
    }, ({ projectId, id }) => {
      const project = selectProject(projectId);
      if (project.error) return failure(project.error);
      if (!templates.length) return failure('Template catalog unavailable. Use the default finding format from list_templates.');
      const template = templatesById.get(id);
      if (!template) return failure('Unknown template ID');
      return result(templateDetails(template));
    });

    function appendFinding(projectId, { idempotencyKey, ...values }) {
      const template = templatesById.get(values.templateId);
      if (values.templateId !== undefined && !template) return { error: 'Unknown template ID' };
      return store.appendFinding(() => {
        const project = selectProject(projectId);
        if (project.error) return project;
        if (values.status !== undefined && !isProjectFindingStatus(values.status, project.data)) {
          return { error: 'Invalid arguments: unknown finding status for this project' };
        }
        return project;
      }, idempotencyKey, appendDigest(values), (id) => {
        const inherited = template ? templateFindingFields(template) : {};
        return newFinding(id, { ...inherited, ...values });
      });
    }

    server.registerTool('append_finding', {
      description: 'Append a report finding. Supply a title or templateId. Explicit fields override template defaults. Submit plain text and separate paragraphs with blank lines. An identical retry returns the original findingId with created:false. Reusing its idempotencyKey for different content returns an error.',
      inputSchema: appendInput.safeExtend(projectInput),
      outputSchema: appendOutcome,
      annotations: appendAnnotations,
    }, ({ projectId, ...values }) => {
      const outcome = appendFinding(projectId, values);
      return outcome.error ? failure(outcome.error) : result(outcome);
    });

    server.registerTool('append_findings', {
      description: 'Append up to 25 report findings to one project. Each item takes the append_finding fields and its own idempotencyKey. Results are in input order and use zero-based indices.',
      inputSchema: z.strictObject({
        ...projectInput,
        findings: z.array(z.unknown()).min(1).max(25).describe(
          `Use append_finding fields per item, excluding projectId. Invalid items return an indexed error. Valid items are committed independently. ${evidenceGuidance}`,
        ),
      }),
      outputSchema: z.object({
        results: z.array(z.union([
          appendOutcome.extend({ index: z.number().int() }),
          z.object({ index: z.number().int(), error: z.string() }),
        ])),
      }),
      annotations: appendAnnotations,
    }, ({ projectId, findings }) => {
      const project = selectProject(projectId);
      if (project.error) return failure(project.error);
      const results = findings.map((finding, index) => {
        const parsed = appendInput.safeParse(finding);
        if (!parsed.success) return { index, error: z.prettifyError(parsed.error) };
        return { index, ...appendFinding(project.id, parsed.data) };
      });
      return result({ results });
    });

    if (canManage) {
      server.registerTool('list_findings', {
        description: 'Page through compact finding summaries. Filter by severity, status, or a case-insensitive substring of finding identifiers, titles, and report metadata.',
        inputSchema: z.strictObject({
          ...projectInput,
          query: queryInput,
          severity: severity.optional(),
          status: findingStatus.optional(),
          limit: z.number().int().min(1).max(50).default(20),
          offset: offsetInput.default(0),
        }),
        outputSchema: z.object({ findings: z.array(findingSummary), ...pageInfo }),
        annotations: readOnly,
      }, ({ projectId, query, severity, status, limit, offset }) => {
        const project = selectProject(projectId, true);
        if (project.error) return failure(project.error);
        const rows = statements.mcpFindingSummaries.all({
          ownerId: project.owner_id, projectId: project.id, query: query ? normalizeWorkspaceId(query) : null,
          severity: severity ?? null, status: status ?? null, limit: limit + 1, offset,
        });
        const findings = rows.slice(0, limit).map(({ confidence, templateId, category, ...summary }) => ({
          ...summary,
          ...(confidence !== null ? { confidence } : {}),
          ...(templateId !== null ? { templateId } : {}),
          ...(category !== null ? { category } : {}),
        }));
        return result({ findings, ...pagination(rows.length > limit, offset, limit) });
      });

      server.registerTool('get_finding', {
        description: 'Get a full report finding by ID or by a Peng link copied from the workspace, including its stored rich-text report fields. The second URL segment is the finding ID. Use only links from the connected Peng instance.',
        inputSchema: z.strictObject({
          ...projectInput,
          id: projectIdSchema.optional(),
          url: z.url({ protocol: /^https?$/ }).optional().describe('A Peng link with the project and finding IDs in its path.'),
        }).refine(({ id, url, projectId }) => url === undefined ? id !== undefined : id === undefined && projectId === undefined, {
          message: 'Supply either a finding ID (with optional local projectId) or a Peng finding URL',
        }),
        outputSchema: z.object({ finding: findingDetail }),
        annotations: readOnly,
      }, ({ projectId, id, url }) => {
        const address = url ? new URL(url) : null;
        const link = address
          ? readWorkspacePath(address.pathname) ?? readLegacyWorkspaceLink(address.searchParams)
          : null;
        if (link && (!projectIdSchema.safeParse(link.projectId).success
          || !projectIdSchema.safeParse(link.findingId).success)) return failure('Invalid Peng finding link');
        const project = selectProject(link ? link.projectId : projectId, true);
        if (project.error) return failure(project.error);
        if (link && link.projectId !== project.id) return failure('Finding link is for a different project');
        const row = statements.mcpFinding.get(project.owner_id, project.id, link ? link.findingId : normalizeWorkspaceId(id));
        return row ? result({ finding: JSON.parse(row.data) }) : failure('Unknown finding ID');
      });

      server.registerTool('update_finding', {
        description: 'Patch the supplied report fields of an existing finding. Use the finding ID from list_findings or the second segment of a Peng finding URL. Supply plain text for report fields. An empty string or array clears the corresponding text or list.',
        inputSchema: z.strictObject({ ...projectInput, id: projectIdSchema, patch: findingPatch }),
        outputSchema: z.object({ findingId: z.string(), updated: z.literal(true) }),
        annotations: { idempotentHint: true, openWorldHint: false },
      }, ({ projectId, id, patch }) => {
        const findingId = normalizeWorkspaceId(id);
        const project = selectProject(projectId, true);
        if (project.error) return failure(project.error);
        if (patch.status !== undefined && !isProjectFindingStatus(patch.status, project.data)) {
          return failure('Invalid arguments: unknown finding status for this project');
        }
        if (patch.templateId !== undefined && !templatesById.has(patch.templateId)) return failure('Unknown template ID');
        const { changes } = statements.mcpUpdateFinding.run({
          ownerId: project.owner_id, projectId: project.id, findingId,
          patch: JSON.stringify(renderFindingFields(patch)),
        });
        return changes ? result({ findingId, updated: true }) : failure('Unknown finding ID');
      });
    }

    return server;
  }, { maxRequestBodySize, maxSubscriptions: 0 });

  return {
    handle: toNodeHandler(handler, { maxRequestBodySize }),
    close: () => handler.close(),
  };
}
