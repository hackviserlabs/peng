import type { SeverityColorMap } from '../types';
import type { Severity } from '../types';

export const TEMPLATE_INSTRUCTIONS_LIMIT = 16_384;

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
