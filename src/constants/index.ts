import type { SeverityColorMap } from '../types';
import type { CustomFindingStatus, FINDING_STATUSES } from '../types/findingStatus';
import type { Severity } from '../types';

export const TEMPLATE_INSTRUCTIONS_LIMIT = 16_384;
// Match the server finding schema.
export const TRIAGE_NOTES_LIMIT = 24_000;
export const FINDING_METADATA_LIMIT = 2_048;
export const FINDING_METADATA_LIST_LIMIT = 100;

const FINDING_STATUS_COLORS: Record<(typeof FINDING_STATUSES)[number], string> = {
    New: 'bg-sky-500/10 text-sky-400',
    Open: 'bg-zinc-500/10 text-zinc-400',
    Verified: 'bg-violet-500/10 text-violet-400',
    'False Positive': 'bg-zinc-500/10 text-zinc-300',
    Duplicate: 'bg-indigo-500/10 text-indigo-400',
    'Accepted Risk': 'bg-yellow-500/10 text-yellow-400',
    Fixed: 'bg-green-500/10 text-green-400',
};

export function findingStatusAppearance(status: string, customStatuses: readonly CustomFindingStatus[] = []) {
    const color = customStatuses.find(({ name }) => name === status)?.color;
    if (color) {
        return { className: 'text-zinc-100', style: { backgroundColor: `${color}26`, boxShadow: `inset 0 -2px ${color}` } };
    }
    const builtin = status as keyof typeof FINDING_STATUS_COLORS;
    return {
        className: Object.hasOwn(FINDING_STATUS_COLORS, builtin) ? FINDING_STATUS_COLORS[builtin] : 'bg-zinc-500/10 text-zinc-400',
    };
}

export const SEVERITY_COLORS: SeverityColorMap = {
    Critical: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/20', dot: 'bg-red-500' },
    High: { bg: 'bg-orange-500/10', text: 'text-orange-500', border: 'border-orange-500/20', dot: 'bg-orange-500' },
    Medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-500', border: 'border-yellow-500/20', dot: 'bg-yellow-500' },
    Low: { bg: 'bg-blue-500/10', text: 'text-blue-500', border: 'border-blue-500/20', dot: 'bg-blue-500' },
    Info: { bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/20', dot: 'bg-zinc-500' },
};

export type TemplateCategory =
    | 'Injection'
    | 'XSS'
    | 'Broken Access Control'
    | 'Authentication'
    | 'Cryptographic Failures'
    | 'Security Misconfiguration'
    | 'Information Disclosure'
    | 'SSRF'
    | 'Business Logic'
    | 'API Security'
    | 'Network & Infrastructure'
    | 'SSL/TLS'
    | 'Mobile'
    | 'Cloud'
    | 'Other';

export interface FindingTemplate {
    id: string;
    title: string;
    category: TemplateCategory;
    severity: Severity;
    cwe?: string;
    cvss?: string;
    owasp?: string;
    tags: string[];
    // Optional metadata hints
    url?: string;
    method?: string;
    parameter?: string;
    affectedHost?: string;
    port?: string;
    // Content
    description: string;
    impact: string;
    remediation: string;
    references?: string;
}
