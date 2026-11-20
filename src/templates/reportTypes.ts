import { type Project, type Finding, type Severity, type FindingStatus } from '../types';
import { findingStatusNames } from '../types/findingStatus';

export type ReportFinding = Omit<Finding, 'notes' | 'triageNotes'>;

export function toReportFinding(finding: Finding): ReportFinding {
    const reportFinding: ReportFinding & { notes?: string; triageNotes?: string } = { ...finding };
    delete reportFinding.notes;
    delete reportFinding.triageNotes;
    return reportFinding;
}

export interface ReportStats {
    total: number;
    bySeverity: Record<Severity, number>;
    byStatus: Record<FindingStatus, number>;
    byCategory: Map<string, number>;
}

export interface ReportData {
    project: Project;
    findings: ReportFinding[];
    generatedAt: string;
    stats: ReportStats;
}

export interface ReportTemplate {
    id: string;
    name: string;
    description: string;
    component: React.ComponentType<{ data: ReportData }>;
}

export function buildReportData(project: Project, findings: Finding[]): ReportData {
    const severityOrder: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

    const sorted = findings.map(toReportFinding).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    const stats: ReportStats = {
        total: sorted.length,
        bySeverity: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
        byStatus: Object.fromEntries(findingStatusNames(project.customFindingStatuses, sorted.map(finding => finding.status))
            .map(status => [status, 0])),
        byCategory: new Map(),
    };
    for (const f of sorted) {
        stats.bySeverity[f.severity]++;
        stats.byStatus[f.status]++;
        const category = f.category?.trim() || '';
        stats.byCategory.set(category, (stats.byCategory.get(category) ?? 0) + 1);
    }

    return {
        project,
        findings: sorted,
        generatedAt: new Date().toISOString(),
        stats,
    };
}
