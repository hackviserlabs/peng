import { useState, useRef, useEffect } from 'react';
import { MoreHorizontal, Copy, Trash2 } from 'lucide-react';
import { SEVERITY_COLORS } from '../../constants';
import type { Finding } from '../../types';
import FindingStatusBadge from '../ui/FindingStatusBadge';
import type { CustomFindingStatus } from '../../types/findingStatus';

interface FindingListProps {
    findings: Finding[];
    customStatuses?: readonly CustomFindingStatus[];
    selectedFindingId: string | null;
    onSelectFinding: (id: string) => void;
    onDeleteFinding: (id: string) => void;
    onDuplicateFinding: (id: string) => void;
}

export default function FindingList({
    findings,
    customStatuses,
    selectedFindingId,
    onSelectFinding,
    onDeleteFinding,
    onDuplicateFinding,
}: FindingListProps) {
    const [menuOpenId, setMenuOpenId] = useState<string | null>(null);
    const menuRef = useRef<HTMLDivElement>(null);

    // Close menu on outside click
    useEffect(() => {
        if (!menuOpenId) return;
        const handleClick = (e: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
                setMenuOpenId(null);
            }
        };
        // Use setTimeout to avoid the same click that opened the menu from closing it
        const timer = setTimeout(() => document.addEventListener('click', handleClick), 0);
        return () => { clearTimeout(timer); document.removeEventListener('click', handleClick); };
    }, [menuOpenId]);

    return (
        <div className="flex-1 overflow-y-auto p-3 space-y-1">
            {findings.map((f) => (
                <div
                    key={f.id}
                    onClick={() => onSelectFinding(f.id)}
                    className={`group flex flex-col p-3 cursor-pointer rounded-lg transition-all relative ${selectedFindingId === f.id
                        ? 'bg-zinc-800/80 shadow-sm'
                        : 'hover:bg-zinc-800/40'
                        }`}
                >
                    <div className="flex items-start justify-between mb-2">
                        <span
                            className={`text-sm font-medium leading-snug pr-6 ${selectedFindingId === f.id
                                ? 'text-white'
                                : 'text-zinc-300 group-hover:text-white'
                                }`}
                        >
                            {f.title || 'Untitled Finding'}
                        </span>

                        {/* ... menu button */}
                        <button
                            onClick={(e) => { e.stopPropagation(); setMenuOpenId(menuOpenId === f.id ? null : f.id); }}
                            className="absolute top-2.5 right-2 p-1 text-zinc-600 hover:text-zinc-300 hover:bg-zinc-700 opacity-0 group-hover:opacity-100 transition-all rounded"
                        >
                            <MoreHorizontal className="w-4 h-4" />
                        </button>

                        {/* Dropdown */}
                        {menuOpenId === f.id && (
                            <div
                                ref={menuRef}
                                className="absolute top-8 right-2 z-50 bg-zinc-900 border border-zinc-700 rounded-lg shadow-2xl py-1 min-w-[140px]"
                            >
                                <button
                                    onClick={(e) => { e.stopPropagation(); onDuplicateFinding(f.id); setMenuOpenId(null); }}
                                    className="w-full flex items-center gap-2 text-left text-xs text-zinc-300 hover:bg-zinc-800 px-3 py-2 transition-colors"
                                >
                                    <Copy className="w-3.5 h-3.5" />
                                    Duplicate
                                </button>
                                <button
                                    onClick={(e) => { e.stopPropagation(); onDeleteFinding(f.id); setMenuOpenId(null); }}
                                    className="w-full flex items-center gap-2 text-left text-xs text-red-400 hover:bg-red-400/10 px-3 py-2 transition-colors"
                                >
                                    <Trash2 className="w-3.5 h-3.5" />
                                    Delete
                                </button>
                            </div>
                        )}
                    </div>
                    {f.category && <p className="mb-2 text-xs text-zinc-400 break-words">{f.category}</p>}
                    <div className="flex flex-wrap items-center gap-2">
                        <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider ${SEVERITY_COLORS[f.severity].bg} ${SEVERITY_COLORS[f.severity].text}`}
                        >
                            {f.severity}
                        </span>
                        <FindingStatusBadge status={f.status} customStatuses={customStatuses} />
                    </div>
                </div>
            ))}
            {findings.length === 0 && (
                <div className="text-center p-6 text-sm text-zinc-500 mt-4">
                    No findings found.
                </div>
            )}
        </div>
    );
}
