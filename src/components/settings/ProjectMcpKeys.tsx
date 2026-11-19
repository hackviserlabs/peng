import { useEffect, useState, type FormEvent } from 'react';
import { api, errorMessage, projectPath } from '../../lib/api';
import ConfirmModal from '../ui/ConfirmModal';

interface ProjectKey {
    id: string;
    name: string;
    createdAt: string;
}

const button = 'rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-50';
const input = 'min-w-0 rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none';

export default function ProjectMcpKeys({ projectId }: { projectId: string }) {
    const path = `${projectPath(projectId)}/keys`;
    const [keys, setKeys] = useState<ProjectKey[]>();
    const [reload, setReload] = useState(0);
    const [name, setName] = useState('');
    const [issuedKey, setIssuedKey] = useState<string>();
    const [pendingRevoke, setPendingRevoke] = useState<ProjectKey>();
    const [busy, setBusy] = useState(false);
    const [loadError, setLoadError] = useState<string>();
    const [actionError, setActionError] = useState<string>();
    const [copyStatus, setCopyStatus] = useState<string>();

    useEffect(() => {
        let active = true;
        api<ProjectKey[]>(path, 'Loading MCP keys').then(result => {
            if (!active) return;
            setKeys(result);
            setLoadError(undefined);
        }).catch(error => {
            if (active) setLoadError(errorMessage(error));
        });
        return () => { active = false; };
    }, [path, reload]);

    const run = async (operation: () => Promise<void>) => {
        if (busy) return;
        setBusy(true);
        setActionError(undefined);
        try {
            await operation();
            setReload(value => value + 1);
        } catch (error) {
            setActionError(errorMessage(error));
        } finally {
            setBusy(false);
        }
    };

    const issue = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const keyName = name.trim();
        if (!keyName) return;
        void run(async () => {
            const { key } = await api<{ key: string }>(path, 'Creating MCP key', 'POST', { name: keyName }, true);
            setIssuedKey(key);
            setCopyStatus(undefined);
            setName('');
        });
    };

    const revoke = () => {
        if (!pendingRevoke) return;
        const { id } = pendingRevoke;
        setPendingRevoke(undefined);
        void run(async () => {
            await api(`${path}/${encodeURIComponent(id)}`, 'Revoking MCP key', 'DELETE');
            setKeys(previous => previous?.filter(key => key.id !== id));
            setIssuedKey(undefined);
        });
    };

    const copy = async (value: string, message: string) => {
        try {
            await navigator.clipboard.writeText(value);
            setCopyStatus(message);
        } catch {
            setCopyStatus('Clipboard access is unavailable. Select the text and copy it manually.');
        }
    };

    const endpoint = new URL('/mcp', window.location.origin).href;
    const instructions = `Connect to ${endpoint} using Streamable HTTP. Set the Authorization header to Bearer <project MCP key>.`;

    return (
        <section className="space-y-4 border-t border-zinc-800/50 pt-8" aria-label="MCP access">
            <h3 className="text-lg font-semibold text-zinc-100">MCP access</h3>
            <div className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 text-sm text-zinc-300">
                <p>Use Streamable HTTP with this project’s bearer key.</p>
                <dl className="space-y-1 break-all font-mono text-xs text-zinc-300">
                    <div><dt className="inline text-zinc-500">Endpoint </dt><dd className="inline">{endpoint}</dd></div>
                    <div><dt className="inline text-zinc-500">Authorization </dt><dd className="inline">Bearer &lt;project MCP key&gt;</dd></div>
                </dl>
                <button type="button" className={button} onClick={() => void copy(instructions, 'Connection instructions copied.')}>
                    Copy connection instructions
                </button>
            </div>

            <form onSubmit={issue} className="flex flex-wrap items-end gap-2">
                <label className="flex min-w-40 flex-1 flex-col gap-1 text-sm text-zinc-400">
                    Key name
                    <input required maxLength={120} className={input} value={name} onChange={event => setName(event.target.value)} />
                </label>
                <button className={button} disabled={busy || !name.trim()}>Create key</button>
            </form>

            {issuedKey && (
                <div className="space-y-2 rounded-lg border border-emerald-800 bg-emerald-950/40 p-4">
                    <p className="text-sm text-emerald-100">Copy your new key now. It is shown once.</p>
                    <div className="flex flex-wrap gap-2">
                        <input aria-label="New MCP key" className={`${input} flex-1 font-mono`} readOnly
                            value={issuedKey} onFocus={event => event.target.select()} />
                        <button type="button" className={button} onClick={() => void copy(issuedKey, 'Key copied.')}>Copy key</button>
                        <button type="button" className={button} onClick={() => setIssuedKey(undefined)}>Hide key</button>
                    </div>
                </div>
            )}

            {copyStatus && <p role="status" className="text-sm text-zinc-300">{copyStatus}</p>}
            {actionError && <p role="alert" className="text-sm text-red-300">{actionError}</p>}
            {loadError && (
                <p role="alert" className="text-sm text-red-300">
                    {loadError} <button type="button" className="underline" onClick={() => setReload(value => value + 1)}>Retry</button>
                </p>
            )}
            {!keys && !loadError && <p role="status" className="text-sm text-zinc-500">Loading keys…</p>}
            {keys?.length === 0 && <p className="text-sm text-zinc-500">No active MCP keys.</p>}
            {keys && (
                <ul className="divide-y divide-zinc-800">
                    {keys.map(key => (
                        <li key={key.id} className="flex items-center justify-between gap-3 py-3">
                            <div className="min-w-0">
                                <p className="break-words text-sm text-zinc-100">{key.name}</p>
                                <p className="text-xs text-zinc-500">Created {new Date(key.createdAt).toLocaleString()}</p>
                            </div>
                            <button type="button" className={button} disabled={busy} onClick={() => setPendingRevoke(key)}>
                                Revoke
                            </button>
                        </li>
                    ))}
                </ul>
            )}
            <ConfirmModal open={Boolean(pendingRevoke)} title="Revoke MCP key"
                message={`Clients using “${pendingRevoke?.name ?? ''}” will lose access to this project.`}
                confirmLabel="Revoke key" onConfirm={revoke} onCancel={() => setPendingRevoke(undefined)} />
        </section>
    );
}
