import { createDefaultFinding, createDefaultProject, type Finding, type Project } from '../types';

function readRecord(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
}

function readFields<T extends Project | Finding>(defaults: T, record: Record<string, unknown>, optional: keyof T) {
    const fields = { ...defaults };
    const keys = [...Object.keys(defaults), optional] as (keyof T)[];
    for (const key of keys) {
        const value = record[String(key)];
        if (value === undefined) continue;
        if (typeof value !== 'string') throw new Error();
        Object.assign(fields, { [key]: value });
    }
    return fields;
}

export function parseProjectImport(json: string): { project: Project; findings: Finding[] } {
    try {
        const data = readRecord(JSON.parse(json));
        if (!Array.isArray(data.findings)) throw new Error();
        const defaults = createDefaultProject('Imported Project');
        const project = readFields(defaults, readRecord(data.project), 'templateInstructions');
        project.id = defaults.id;
        project.createdAt = defaults.createdAt;
        project.updatedAt = defaults.updatedAt;
        project.name ||= defaults.name;
        if (!['Confidential', 'Internal', 'Public'].includes(project.classification)) throw new Error();

        const findings = data.findings.map((value: unknown): Finding => {
            const defaults = createDefaultFinding(project.id);
            const finding = readFields(defaults, readRecord(value), 'cvssVector');
            finding.id = defaults.id;
            finding.projectId = project.id;
            finding.status ||= defaults.status;
            finding.createdAt ||= defaults.createdAt;
            if (!['Critical', 'High', 'Medium', 'Low', 'Info'].includes(finding.severity)
                || !['Open', 'Fixed', 'Accepted Risk'].includes(finding.status)) throw new Error();
            return finding;
        });
        return { project, findings };
    } catch {
        throw new Error('The import file must contain a valid project and findings.');
    }
}
