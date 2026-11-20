import { createWorkspaceId } from './findingLink';
import type { CustomFindingStatus } from './findingStatus';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type Classification = 'Confidential' | 'Internal' | 'Public';
export type FindingStatus = string;
export const FINDING_CONFIDENCES = ['high', 'medium', 'low'] as const;
export type FindingConfidence = typeof FINDING_CONFIDENCES[number];

export function findingStatusLabel(status: FindingStatus): string {
    return status === 'Open' ? 'Open (legacy)' : status;
}
const SCOPE_TYPES = ['Web App', 'API', 'Network', 'Mobile', 'Other'] as const;
export type ScopeType = typeof SCOPE_TYPES[number];

export interface ScopeItem {
    id: string;
    value: string;
    type: ScopeType;
    included: boolean; // true = In Scope, false = Out of Scope
}

function readScopeItems(scope: string): unknown[] | undefined {
    if (scope === '') return [];
    try {
        const parsed: unknown = JSON.parse(scope);
        if (Array.isArray(parsed)) return parsed;
    } catch { /* Invalid JSON. */ }
}

function validScopeItems(items: unknown[]): ScopeItem[] {
    const ids = new Set<string>();
    return items.filter((item): item is ScopeItem => {
        if (!item || typeof item !== 'object') return false;
        const { id, value, type, included } = item as Partial<ScopeItem>;
        if (typeof id !== 'string' || !id || ids.has(id) || typeof value !== 'string'
            || !type || !SCOPE_TYPES.includes(type) || typeof included !== 'boolean') return false;
        ids.add(id);
        return true;
    });
}

export function isValidScope(scope: string): boolean {
    const items = readScopeItems(scope);
    return items !== undefined && validScopeItems(items).length === items.length;
}

export function parseScopeItems(scope: string): ScopeItem[] {
    return validScopeItems(readScopeItems(scope) ?? []);
}

export function stringifyScopeItems(items: ScopeItem[]): string {
    return JSON.stringify(items);
}

export interface Project {
    id: string;
    name: string;
    clientName: string;
    assessorName: string;
    assessmentDateStart: string;
    assessmentDateEnd: string;
    reportDate: string;
    reportVersion: string;
    classification: Classification;
    scope: string;
    executiveSummary: string;
    templateInstructions?: string;
    customFindingStatuses?: CustomFindingStatus[];
    createdAt: string;
    updatedAt: string;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';

export interface FindingTarget {
    url: string;
    method?: string;
    parameter?: string;
    host?: string;
    port?: string;
}

export const FINDING_TARGET_FIELDS = ['url', 'method', 'parameter', 'host', 'port'] as const;

export interface Finding {
    id: string;
    projectId: string;
    title: string;
    severity: Severity;
    status: FindingStatus;
    confidence?: FindingConfidence;
    triageNotes?: string;
    evidence?: string[];
    targets?: FindingTarget[];
    templateId?: string;
    category?: string;
    tags?: string[];
    // Metadata properties
    url: string;
    method: string;
    parameter: string;
    affectedHost: string;
    port: string;
    cve: string;
    cwe: string;
    cvss: string;
    cvssVector?: string;
    references: string;
    // Content blocks
    description: string;
    poc: string;
    requestResponse: string;
    impact: string;
    remediation: string;
    notes: string;
    createdAt: string;
}

export type UpdateFindingField = <K extends keyof Finding>(field: K, value: Finding[K]) => void;

export interface SeverityColor {
    bg: string;
    text: string;
    border: string;
    dot: string;
}

export type SeverityColorMap = Record<Severity, SeverityColor>;

export function createDefaultProject(name: string): Project {
    const now = new Date().toISOString();
    return {
        id: createWorkspaceId(),
        name,
        clientName: '',
        assessorName: '',
        assessmentDateStart: '',
        assessmentDateEnd: '',
        reportDate: now.split('T')[0],
        reportVersion: '1.0',
        classification: 'Confidential',
        scope: '',
        executiveSummary: '',
        createdAt: now,
        updatedAt: now,
    };
}

export function createDefaultFinding(projectId: string): Finding {
    return {
        id: createWorkspaceId(),
        projectId,
        title: '',
        severity: 'Medium',
        status: 'New',
        url: '',
        method: '',
        parameter: '',
        affectedHost: '',
        port: '',
        cve: '',
        cwe: '',
        cvss: '',
        cvssVector: '',
        references: '',
        description: '',
        poc: '',
        requestResponse: '',
        impact: '',
        remediation: '',
        notes: '',
        createdAt: new Date().toISOString(),
    };
}
