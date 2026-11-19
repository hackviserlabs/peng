import { z } from 'zod';
import { createDefaultFinding } from '../src/types/index.ts';
import { findingStatus, findingConfidence, severity } from './schemas.js';
import { digest } from './store.js';

export { findingStatus, findingConfidence };
const title = z.string().trim().min(1).max(240);
const text = z.string().max(24_000);
const metadata = z.string().max(2_048);
const singleLine = (max) => z.string().trim().min(1).max(max).regex(/^[^\p{Cc}\p{Zl}\p{Zp}]+$/u);

const evidenceLocation = singleLine(2_048).refine((value) => {
  if (/^[a-z]:[\\/]/i.test(value) || !/^[a-z][a-z0-9+.-]*:/i.test(value)) return true;
  try {
    return ['https:', 'http:', 'file:'].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}, 'Expected a file path or an HTTP(S) or file URL');

const target = z.strictObject({
  url: singleLine(2_048),
  method: metadata.optional(),
  parameter: metadata.optional(),
  host: metadata.optional(),
  port: metadata.optional(),
});

export const templateId = z.string().trim().min(1).max(120);
const reportFields = {
  description: text,
  poc: text,
  requestResponse: text,
  impact: text,
  remediation: text,
  notes: text,
  references: text,
};

// Keep the fields in their original append_finding order for stored idempotency digests.
const legacyFields = {
  title,
  severity,
  ...reportFields,
  url: metadata,
  method: metadata,
  parameter: metadata,
  affectedHost: metadata,
  port: metadata,
  cve: metadata,
  cwe: metadata,
  cvss: metadata,
  cvssVector: metadata,
};
const findingFields = {
  ...legacyFields,
  status: findingStatus,
  confidence: findingConfidence,
  triageNotes: text.describe('Plain-text triage notes.'),
  evidence: z.array(evidenceLocation).max(50).describe('Evidence locations as paths or URLs.'),
  targets: z.array(target).max(50),
  templateId,
  category: singleLine(120),
  tags: z.array(singleLine(120)).max(50),
};
const optionalFields = z.strictObject(findingFields).partial();

// Stored records may predate MCP input limits and can include optional metadata.
const storedText = z.string();
export const findingDetails = z.looseObject({
  projectId: z.string(),
  ...Object.fromEntries(Object.keys(legacyFields).map((field) => [field, storedText])),
  cvssVector: storedText.optional(),
  triageNotes: storedText.optional(),
  evidence: z.array(storedText).optional(),
  targets: z.array(z.object({
    url: storedText,
    method: storedText.optional(),
    parameter: storedText.optional(),
    host: storedText.optional(),
    port: storedText.optional(),
  })).optional(),
  tags: z.array(storedText).optional(),
});

export const appendInput = optionalFields.extend({
  idempotencyKey: z.string().trim().min(1).max(200).describe('Scoped to one project. Retrying the same content returns its original findingId with created:false. Reusing the key with different content returns an error.'),
}).refine(({ title, templateId }) => title !== undefined || templateId !== undefined, {
  path: ['title'],
  message: 'Provide a title or a templateId',
});

export const findingPatch = optionalFields.refine((patch) => Object.keys(patch).length > 0, {
  message: 'Provide at least one field to update',
});

const legacyDefaults = Object.fromEntries(Object.keys(legacyFields).map((field) => [
  field, field === 'severity' ? 'Medium' : '',
]));

export function appendDigest(values) {
  // Template defaults live in the catalog. Hash caller input so later catalog edits
  // and changes to the stored finding cannot affect a retry.
  const defaults = values.templateId === undefined ? legacyDefaults : {};
  const normalized = { ...defaults, ...values };
  if (normalized.status === 'New') delete normalized.status;
  return digest(JSON.stringify(normalized));
}

const htmlEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function renderFindingFields(values) {
  const rendered = { ...values };
  for (const field of Object.keys(reportFields)) {
    if (Object.hasOwn(values, field)) rendered[field] = renderText(values[field], field);
  }
  return rendered;
}

function renderText(value, field) {
  if (!value.trim()) return '';
  const escaped = value.replace(/\r\n?/g, '\n').replace(/[&<>"']/g, (char) => htmlEntities[char]);
  if (field === 'requestResponse') return `<pre><code>${escaped}</code></pre>`;
  return escaped.trim().split(/\n(?:[^\S\n]*\n)+/)
    .map((paragraph) => `<p>${paragraph.replaceAll('\n', '<br>')}</p>`).join('');
}

export function newFinding(projectId, values) {
  return { ...createDefaultFinding(projectId), ...legacyDefaults, status: 'New', ...renderFindingFields(values) };
}
