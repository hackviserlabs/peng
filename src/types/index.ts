export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type Classification = 'Confidential' | 'Internal' | 'Public';
export type FindingStatus = 'Open' | 'Fixed' | 'Accepted Risk';
export type ScopeType = 'Web App' | 'API' | 'Network' | 'Mobile' | 'Other';

export interface ScopeItem {
    id: string;
    value: string;
    type: ScopeType;
    included: boolean; // true = In Scope, false = Out of Scope
}

export function parseScopeItems(scope: string): ScopeItem[] {
    try {
        const parsed = JSON.parse(scope);
        if (Array.isArray(parsed)) return parsed;
    } catch { /* not JSON */ }
    return [];
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
    createdAt: string;
    updatedAt: string;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';

export interface Finding {
    id: string;
    projectId: string;
    title: string;
    severity: Severity;
    status: FindingStatus;
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
        id: crypto.randomUUID(),
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
        id: crypto.randomUUID(),
        projectId,
        title: '',
        severity: 'Medium',
        status: 'Open',
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
