export const serverMode = import.meta.env.VITE_SERVER_MODE === 'true';

export class ApiError extends Error {
    readonly status: number;

    constructor(message: string, status: number) {
        super(message);
        this.status = status;
    }
}

export function errorMessage(error: unknown) {
    return error instanceof Error ? error.message : 'An unexpected error occurred.';
}

export async function api<T = void>(
    path: string,
    action: string,
    method = 'GET',
    body?: unknown,
    expectJson = method === 'GET',
): Promise<T> {
    const response = await fetch(path, {
        method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers: method === 'GET' ? undefined : { 'Content-Type': 'application/json' },
        body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    }).catch(() => {
        throw new Error(`${action} failed. Check your connection and try again.`);
    });

    if (!response.ok) {
        if (response.status === 401 && path !== '/api/session' && path !== '/api/login') {
            window.dispatchEvent(new Event('workspace-session-expired'));
        }
        throw new ApiError(`${action} failed (${response.status}).`, response.status);
    }

    if (expectJson) {
        try {
            return await response.json() as T;
        } catch {
            throw new Error(`${action} returned an invalid response.`);
        }
    }
    return undefined as T;
}

export function projectPath(id: string) {
    return `/api/projects/${encodeURIComponent(id)}`;
}
