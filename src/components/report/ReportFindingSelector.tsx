import { useEffect, useRef, useState } from 'react';
import { SEVERITY_COLORS } from '../../constants';
import { findingStatusLabel, type Finding, type FindingStatus } from '../../types';

import FindingStatusBadge from '../ui/FindingStatusBadge';
import { findingStatusNames, type CustomFindingStatus } from '../../types/findingStatus';

interface ReportFindingSelectorProps {
    findings: Finding[];
    customStatuses?: readonly CustomFindingStatus[];
    onCancel: () => void;
    onPreview: (findingIds: ReadonlySet<string>) => void;
}

const secondaryButton = 'rounded-lg bg-zinc-800 px-3.5 py-2 text-xs font-medium text-zinc-300 transition-colors hover:bg-zinc-700 disabled:opacity-50 disabled:hover:bg-zinc-800';

function toggleItem<T>(items: ReadonlySet<T>, item: T) {
    const next = new Set(items);
    if (!next.delete(item)) next.add(item);
    return next;
}

export default function ReportFindingSelector({ findings, customStatuses, onCancel, onPreview }: ReportFindingSelectorProps) {
    const dialogRef = useRef<HTMLDialogElement>(null);
    const [includedIds, setIncludedIds] = useState(() => new Set(findings.map(({ id }) => id)));
    const [statuses, setStatuses] = useState(() => new Set<FindingStatus>());

    useEffect(() => {
        const dialog = dialogRef.current;
        dialog?.showModal();
        return () => dialog?.close();
    }, []);

    const visibleFindings = findings.filter(({ status }) => statuses.size === 0 || statuses.has(status));
    const includedFindings = findings.filter(({ id }) => includedIds.has(id));
    const includedVisibleCount = visibleFindings.filter(({ id }) => includedIds.has(id)).length;

    return (
        <dialog
            ref={dialogRef}
            aria-labelledby="report-selector-title"
            onCancel={(event) => {
                event.preventDefault();
                onCancel();
            }}
            className="m-auto w-[calc(100%-2rem)] max-w-2xl overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900 text-zinc-300 shadow-2xl backdrop:bg-black/60 backdrop:backdrop-blur-sm print:hidden"
        >
            <div className="flex max-h-[85dvh] flex-col">
                <header className="border-b border-zinc-800 px-5 py-4">
                    <h2 id="report-selector-title" className="text-sm font-semibold text-white">Select report findings</h2>
                    <p className="mt-1 text-xs text-zinc-400">Findings added while this window is open start unchecked.</p>
                </header>
                <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
                    <fieldset className="mb-4">
                        <legend className="mb-2 text-xs font-medium text-zinc-300">Show by status</legend>
                        <div className="flex flex-wrap gap-2">
                            {findingStatusNames(customStatuses, findings.map(finding => finding.status)).map((status) => (
                                <label key={status} className="flex cursor-pointer items-center gap-2 rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs">
                                    <input
                                        type="checkbox"
                                        checked={statuses.has(status)}
                                        onChange={() => setStatuses((current) => toggleItem(current, status))}
                                        className="accent-emerald-500"
                                    />
                                    {findingStatusLabel(status)}
                                </label>
                            ))}
                        </div>
                    </fieldset>
                    <div className="mb-3 flex flex-wrap gap-2">
                        <button type="button" className={secondaryButton} disabled={!findings.length} onClick={() => setIncludedIds(new Set(findings.map(({ id }) => id)))}>
                            Select all
                        </button>
                        <button type="button" className={secondaryButton} disabled={!includedFindings.length} onClick={() => setIncludedIds(new Set())}>
                            Clear selection
                        </button>
                        {statuses.size > 0 && (
                            <button type="button" className={secondaryButton} disabled={!visibleFindings.length} onClick={() => setIncludedIds(new Set(visibleFindings.map(({ id }) => id)))}>
                                Select visible only
                            </button>
                        )}
                    </div>
                    <p role="status" className="mb-3 text-xs text-zinc-400">
                        {includedFindings.length} of {findings.length} selected · {includedVisibleCount} of {visibleFindings.length} visible selected
                    </p>
                    {visibleFindings.length === 0 ? (
                        <p className="rounded-lg border border-zinc-800 p-4 text-sm text-zinc-400">
                            {findings.length === 0 ? 'This project has no findings.' : 'No findings match the selected statuses.'}
                        </p>
                    ) : (
                        <ul aria-label="Findings" className="divide-y divide-zinc-800 rounded-lg border border-zinc-800">
                            {visibleFindings.map((finding) => (
                                <li key={finding.id}>
                                    <label className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5 hover:bg-zinc-800/50">
                                        <input
                                            type="checkbox"
                                            checked={includedIds.has(finding.id)}
                                            onChange={() => setIncludedIds((current) => toggleItem(current, finding.id))}
                                            className="accent-emerald-500"
                                        />
                                        <span className="min-w-0 flex-1 wrap-anywhere text-sm text-zinc-200">{finding.title || 'Untitled Finding'}</span>
                                        <span className={`text-xs font-medium ${SEVERITY_COLORS[finding.severity].text}`}>{finding.severity}</span>
                                        <FindingStatusBadge status={finding.status} customStatuses={customStatuses} />
                                    </label>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
                <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-zinc-800 px-5 py-4">
                    {includedFindings.length === 0 && <span className="mr-auto text-xs text-zinc-400">The report will contain no findings.</span>}
                    <button type="button" className={secondaryButton} onClick={onCancel}>Cancel</button>
                    <button
                        type="button"
                        className="rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-emerald-500"
                        onClick={() => onPreview(new Set(includedFindings.map(({ id }) => id)))}
                    >
                        Preview report
                    </button>
                </footer>
            </div>
        </dialog>
    );
}
