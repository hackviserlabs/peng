import { z } from 'zod';
import { FINDING_STATUSES, FINDING_STATUS_NAME_LIMIT, isCustomFindingStatusList } from '../src/types/findingStatus.ts';

export const username = z.string().min(1).max(120);
export const password = z.string().min(1).max(1024);
export const severity = z.enum(['Critical', 'High', 'Medium', 'Low', 'Info']);

export const id = z.string().min(1).max(255);
const string = z.string();
const text = z.string().max(24_000);
const metadata = z.string().max(2_048);

export const credentials = z.strictObject({ username, password });
export const keyRequest = z.strictObject({
  name: z.string().trim().min(1).max(120),
  access: z.enum(['append', 'manage']).default('append'),
});

const customFindingStatus = z.strictObject({
  name: z.string(),
  color: z.string(),
});

export const project = z.strictObject({
  id,
  name: string,
  clientName: string,
  assessorName: string,
  assessmentDateStart: string,
  assessmentDateEnd: string,
  reportDate: string,
  reportVersion: string,
  classification: z.enum(['Confidential', 'Internal', 'Public']),
  scope: string,
  executiveSummary: string,
  createdAt: string,
  updatedAt: string,
  templateInstructions: z.string().max(16_384).optional(),
  customFindingStatuses: z.array(customFindingStatus).refine(isCustomFindingStatusList).optional(),
});

export const findingStatus = z.string().min(1).max(FINDING_STATUS_NAME_LIMIT);

const builtInStatuses = new Set(FINDING_STATUSES);
export function isProjectFindingStatus(status, projectData) {
  return builtInStatuses.has(status)
    || (JSON.parse(projectData).customFindingStatuses ?? []).some(({ name }) => name === status);
}
export const findingConfidence = z.enum(['high', 'medium', 'low']);
export const findingTarget = z.strictObject({
  url: metadata,
  method: metadata.optional(),
  parameter: metadata.optional(),
  host: metadata.optional(),
  port: metadata.optional(),
});

export const finding = z.strictObject({
  id,
  projectId: id,
  title: string,
  severity,
  status: findingStatus,
  url: string,
  method: string,
  parameter: string,
  affectedHost: string,
  port: string,
  cve: string,
  cwe: string,
  cvss: string,
  cvssVector: string.optional(),
  references: string,
  description: string,
  poc: string,
  requestResponse: string,
  impact: string,
  remediation: string,
  notes: string,
  createdAt: string,
  confidence: findingConfidence.nullish(),
  triageNotes: text.optional(),
  evidence: z.array(metadata).max(100).optional(),
  targets: z.array(findingTarget).max(100).optional(),
  templateId: metadata.optional(),
  category: metadata.optional(),
  tags: z.array(metadata).max(100).optional(),
});
