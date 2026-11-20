const uuidPattern = /^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/;

function toBase64Url(bytes: string) {
    return btoa(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(segment: string) {
    const bytes = atob(segment.replaceAll('-', '+').replaceAll('_', '/'));
    if (toBase64Url(bytes) !== segment) throw new Error('Invalid ID encoding');
    return bytes;
}

export function normalizeWorkspaceId(id: string) {
    if (!uuidPattern.test(id)) return id;
    const hex = id.replaceAll('-', '');
    const bytes = Array.from({ length: 16 }, (_, index) => parseInt(hex.slice(index * 2, index * 2 + 2), 16));
    return toBase64Url(String.fromCharCode(...bytes));
}

export function createWorkspaceId() {
    return normalizeWorkspaceId(crypto.randomUUID());
}

function isCompactId(id: string) {
    return /^[\w-]{21}[AQgw]$/.test(id);
}

function encodeId(id: string) {
    const normalized = normalizeWorkspaceId(id);
    if (isCompactId(normalized)) return normalized;
    // A prefix distinguishes older arbitrary IDs from compact UUIDs.
    const bytes = new TextEncoder().encode(id);
    return '~' + toBase64Url(Array.from(bytes, byte => String.fromCharCode(byte)).join(''));
}

function decodeId(segment: string) {
    if (segment.startsWith('~')) {
        const bytes = Uint8Array.from(fromBase64Url(segment.slice(1)), char => char.charCodeAt(0));
        return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) || null;
    }
    return isCompactId(segment) ? segment : null;
}

export function workspacePath(projectId: string | null, findingId: string | null, settings = false) {
    if (!projectId) return '/';
    const project = '/' + encodeId(projectId);
    if (settings) return project + '/settings';
    return findingId ? project + '/' + encodeId(findingId) : project;
}

export function readWorkspacePath(pathname: string) {
    const [, project, finding, ...rest] = pathname.replace(/\/$/, '').split('/');
    if (!project || rest.length) return null;
    try {
        const projectId = decodeId(project);
        const settings = finding === 'settings';
        const findingId = finding && !settings ? decodeId(finding) : null;
        if (projectId && (!finding || settings || findingId)) return { projectId, findingId, settings };
    } catch {
        // An invalid segment cannot identify a workspace record.
    }
    return null;
}

export function readLegacyWorkspaceLink(params: URLSearchParams) {
    const projectId = params.get('project');
    const findingId = params.get('finding');
    return {
        projectId: projectId ? normalizeWorkspaceId(projectId) : null,
        findingId: findingId ? normalizeWorkspaceId(findingId) : null,
        settings: params.get('view') === 'settings',
    };
}
