import { useState } from 'react';

export default function LocalMcpAccess() {
    const endpoint = new URL('/mcp', window.location.origin).href;
    const [copyStatus, setCopyStatus] = useState<string>();

    const copyEndpoint = async () => {
        try {
            await navigator.clipboard.writeText(endpoint);
            setCopyStatus('Endpoint copied.');
        } catch {
            setCopyStatus('Clipboard access is unavailable. Select the endpoint and copy it manually.');
        }
    };

    return (
        <section className="space-y-4 border-t border-zinc-800/50 pt-8" aria-label="MCP access">
            <h3 className="text-lg font-semibold text-zinc-100">MCP access</h3>
            <div className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 text-sm text-zinc-300">
                <p>Connect using Streamable HTTP. Authentication is disabled in local mode.</p>
                <p className="break-all font-mono text-xs"><span className="text-zinc-500">Endpoint </span>{endpoint}</p>
                <button type="button" onClick={() => void copyEndpoint()}
                    className="rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800">
                    Copy endpoint
                </button>
                {copyStatus && <p role="status">{copyStatus}</p>}
            </div>
            <p className="text-sm text-zinc-400">
                Run <code>list_projects</code> in your MCP client and use the ID of the project you want as
                the <code>projectId</code> in project-specific tool calls.
            </p>
        </section>
    );
}
