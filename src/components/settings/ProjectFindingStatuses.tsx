import { useState, type FormEvent } from 'react';
import { CircleDot, Plus } from 'lucide-react';
import { FINDING_STATUS_NAME_LIMIT, isCustomFindingStatusList, type CustomFindingStatus } from '../../types/findingStatus';

const DEFAULT_COLOR = '#34d399';

interface ProjectFindingStatusesProps {
    statuses?: readonly CustomFindingStatus[];
    onChange: (statuses: CustomFindingStatus[]) => void;
}

export default function ProjectFindingStatuses({ statuses = [], onChange }: ProjectFindingStatusesProps) {
    const [name, setName] = useState('');
    const [color, setColor] = useState(DEFAULT_COLOR);
    const [error, setError] = useState('');

    function addStatus(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        const next = [...statuses, { name: name.trim(), color }];
        if (!isCustomFindingStatusList(next)) {
            setError('Enter a unique status name. Built-in names are reserved.');
            return;
        }
        onChange(next);
        setName('');
        setColor(DEFAULT_COLOR);
        setError('');
    }

    return (
        <section aria-labelledby="project-finding-statuses" className="space-y-3 print:hidden">
            <h3 id="project-finding-statuses" className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
                <CircleDot className="size-5 text-emerald-400/70" /> Finding statuses
            </h3>
            {statuses.length > 0 && (
                <ul className="divide-y divide-zinc-800 rounded-lg border border-zinc-800">
                    {statuses.map(({ name, color }) => (
                        <li key={name} className="flex items-center justify-between gap-3 px-3 py-2 text-sm text-zinc-200">
                            <span className="min-w-0 wrap-anywhere">{name}</span>
                            <input
                                type="color"
                                aria-label={`Color for ${name}`}
                                value={color}
                                onChange={(event) => {
                                    const nextColor = event.target.value;
                                    onChange(statuses.map(status => status.name === name ? { ...status, color: nextColor } : status));
                                }}
                                className="h-8 w-10 shrink-0 cursor-pointer rounded border border-zinc-700 bg-zinc-900 p-1"
                            />
                        </li>
                    ))}
                </ul>
            )}
            <form onSubmit={addStatus} className="flex flex-wrap items-end gap-3">
                <label className="flex min-w-36 flex-1 flex-col gap-1.5 text-xs text-zinc-400">
                    New status
                    <input
                        value={name}
                        onChange={(event) => { setName(event.target.value); setError(''); }}
                        maxLength={FINDING_STATUS_NAME_LIMIT}
                        placeholder="e.g. Ready"
                        className="h-9 rounded-lg border border-zinc-800 bg-zinc-900 px-3 text-sm text-zinc-200"
                    />
                </label>
                <label className="flex flex-col gap-1.5 text-xs text-zinc-400">
                    Color
                    <input type="color" value={color} onChange={(event) => setColor(event.target.value)}
                        className="h-9 w-12 cursor-pointer rounded-lg border border-zinc-700 bg-zinc-900 p-1" />
                </label>
                <button type="submit" disabled={!name.trim()}
                    className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-500/10 px-3 text-xs font-medium text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50">
                    <Plus className="size-3.5" /> Add status
                </button>
            </form>
            {error && <p role="alert" className="text-xs text-rose-400">{error}</p>}
        </section>
    );
}
