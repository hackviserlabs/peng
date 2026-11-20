import {
    createDefaultFinding, createDefaultProject, FINDING_CONFIDENCES,
    FINDING_TARGET_FIELDS, isValidScope, type Finding, type FindingTarget, type Project,
} from '../types';
import { findingStatusNames, isCustomFindingStatusList } from '../types/findingStatus';
import { sanitizeRichText } from './richText';
import { FINDING_METADATA_LIMIT, FINDING_METADATA_LIST_LIMIT, TEMPLATE_INSTRUCTIONS_LIMIT, TRIAGE_NOTES_LIMIT } from '../constants';

const RICH_FINDING_FIELDS = ['description', 'impact', 'remediation', 'poc', 'requestResponse', 'references', 'notes'] as const;

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

function readText(value: unknown, field: string, limit: number): string {
    if (typeof value !== 'string' || value.length > limit) {
        throw new Error(`${field} must be text of at most ${limit} characters.`);
    }
    return value;
}

function readList(value: unknown, field: string): unknown[] {
    if (!Array.isArray(value) || value.length > FINDING_METADATA_LIST_LIMIT) {
        throw new Error(`${field} must be a list of at most ${FINDING_METADATA_LIST_LIMIT} entries.`);
    }
    return value;
}

function readTarget(value: unknown): FindingTarget {
    const record = readRecord(value);
    if (Object.keys(record).some(key => !FINDING_TARGET_FIELDS.some(field => field === key))) {
        throw new Error('Targets support URL, method, parameter, host and port.');
    }
    const target: FindingTarget = { url: readText(record.url, 'Target URL', FINDING_METADATA_LIMIT) };
    for (const field of FINDING_TARGET_FIELDS) {
        if (field !== 'url' && record[field] !== undefined) {
            target[field] = readText(record[field], `Target ${field}`, FINDING_METADATA_LIMIT);
        }
    }
    return target;
}

function readTriageMetadata(finding: Finding, record: Record<string, unknown>) {
    if (record.confidence !== undefined) {
        const confidence = FINDING_CONFIDENCES.find(value => value === record.confidence);
        if (confidence === undefined) throw new Error('Finding confidence must be high, medium or low.');
        finding.confidence = confidence;
    }

    for (const field of ['templateId', 'category', 'triageNotes'] as const) {
        if (record[field] === undefined) continue;
        const limit = field === 'triageNotes' ? TRIAGE_NOTES_LIMIT : FINDING_METADATA_LIMIT;
        finding[field] = readText(record[field], field, limit);
    }
    for (const field of ['evidence', 'tags'] as const) {
        if (record[field] === undefined) continue;
        finding[field] = readList(record[field], field).map(value => readText(value, field, FINDING_METADATA_LIMIT));
    }
    if (record.targets !== undefined) finding.targets = readList(record.targets, 'Targets').map(readTarget);
}

export function parseProjectImport(json: string): { project: Project; findings: Finding[] } {
    try {
        const data = readRecord(JSON.parse(json));
        if (!Array.isArray(data.findings)) throw new Error();
        const defaults = createDefaultProject('Imported Project');
        const projectRecord = readRecord(data.project);
        const project = readFields(defaults, projectRecord, 'templateInstructions');
        const customStatuses = projectRecord.customFindingStatuses;
        if (customStatuses !== undefined) {
            if (!isCustomFindingStatusList(customStatuses)) throw new Error('The import file contains invalid custom finding statuses.');
            project.customFindingStatuses = customStatuses;
        }
        const statuses = findingStatusNames(project.customFindingStatuses);
        project.id = defaults.id;
        project.createdAt = defaults.createdAt;
        project.updatedAt = defaults.updatedAt;
        project.name ||= defaults.name;
        if (!['Confidential', 'Internal', 'Public'].includes(project.classification)) throw new Error();

        const findings = data.findings.map((value: unknown): Finding => {
            const defaults = createDefaultFinding(project.id);
            const record = readRecord(value);
            const finding = readFields(defaults, record, 'cvssVector');
            finding.id = defaults.id;
            finding.projectId = project.id;
            finding.status ||= defaults.status;
            finding.createdAt ||= defaults.createdAt;
            if (!['Critical', 'High', 'Medium', 'Low', 'Info'].includes(finding.severity)
                || !statuses.includes(finding.status)) throw new Error();
            readTriageMetadata(finding, record);
            return finding;
        });
        if (!isValidScope(project.scope)) throw new Error('The import file contains invalid project scope entries.');
        if ((project.templateInstructions?.length ?? 0) > TEMPLATE_INSTRUCTIONS_LIMIT) {
            throw new Error(`Template instructions must be at most ${TEMPLATE_INSTRUCTIONS_LIMIT} characters.`);
        }
        project.executiveSummary = sanitizeRichText(project.executiveSummary);
        for (const finding of findings) {
            for (const field of RICH_FINDING_FIELDS) finding[field] = sanitizeRichText(finding[field]);
        }
        return { project, findings };
    } catch (error) {
        const message = error instanceof SyntaxError ? '' : error instanceof Error ? error.message : '';
        throw new Error(message || 'The import file must contain a valid project and findings.');
    }
}
