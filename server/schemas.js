import { z } from 'zod';

export const username = z.string().min(1).max(120);
export const password = z.string().min(1).max(1024);
export const severity = z.enum(['Critical', 'High', 'Medium', 'Low', 'Info']);

const id = z.string().min(1).max(255);
const string = z.string();

export const credentials = z.strictObject({ username, password });
export const keyRequest = z.strictObject({ name: z.string().trim().min(1).max(120) });

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
});

export const finding = z.strictObject({
  id,
  projectId: id,
  title: string,
  severity,
  status: z.enum(['Open', 'Fixed', 'Accepted Risk']),
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
});
