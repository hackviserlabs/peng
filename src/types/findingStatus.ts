export const FINDING_STATUSES = ['New', 'Open', 'Verified', 'False Positive', 'Duplicate', 'Accepted Risk', 'Fixed'] as const;
export const FINDING_STATUS_NAME_LIMIT = 120;

export interface CustomFindingStatus {
    name: string;
    color: string;
}

export function findingStatusNames(customStatuses: readonly CustomFindingStatus[] = [], existing: readonly string[] = []): string[] {
    return [...new Set([...FINDING_STATUSES, ...customStatuses.map(({ name }) => name), ...existing])];
}

export function isCustomFindingStatusList(value: unknown): value is CustomFindingStatus[] {
    if (!Array.isArray(value)) return false;
    const names = new Set<string>(FINDING_STATUSES.map(name => name.toLowerCase()));
    return value.every((item: unknown) => {
        if (item === null || typeof item !== 'object') return false;
        const { name, color } = item as Partial<CustomFindingStatus>;
        if (typeof name !== 'string' || !name || name !== name.trim() || name.length > FINDING_STATUS_NAME_LIMIT
            || /[\r\n]/.test(name) || typeof color !== 'string' || !/^#[\da-f]{6}$/i.test(color)) return false;
        const key = name.toLowerCase();
        if (names.has(key)) return false;
        names.add(key);
        return true;
    });
}
