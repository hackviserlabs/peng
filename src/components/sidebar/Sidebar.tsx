import { useState } from 'react';
import { Settings, Filter, FileOutput, BookOpen } from 'lucide-react';
import SidebarHeader from './SidebarHeader';
import FindingList from './FindingList';
import type { Finding, Severity, FindingStatus } from '../../types';
import { findingStatusLabel } from '../../types';
import { findingStatusNames, type CustomFindingStatus } from '../../types/findingStatus';
import { ALL_TEMPLATES } from '../../data/templates';

const SEVERITY_ORDER: Record<Severity, number> = {
    Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
};

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

function compareOptional<T>(a: T | undefined, b: T | undefined, compare: (a: T, b: T) => number) {
    if (a === undefined) return b === undefined ? 0 : 1;
    if (b === undefined) return -1;
    return compare(a, b);
}

function creationTime(finding: Finding) {
    const time = Date.parse(finding.createdAt);
    return Number.isFinite(time) ? time : undefined;
}

function cvssScore(finding: Finding) {
    const value = finding.cvss?.trim();
    const score = value ? Number(value) : NaN;
    return score >= 0 && score <= 10 ? score : undefined;
}

const SORT_OPTIONS = {
    newest: { label: 'Newest first', compare: (a, b) => compareOptional(creationTime(a), creationTime(b), (x, y) => y - x) },
    oldest: { label: 'Oldest first', compare: (a, b) => compareOptional(creationTime(a), creationTime(b), (x, y) => x - y) },
    severity: { label: 'Severity: highest first', compare: (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] },
    severityAsc: { label: 'Severity: lowest first', compare: (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] },
    cvssDesc: { label: 'CVSS: highest first', compare: (a, b) => compareOptional(cvssScore(a), cvssScore(b), (x, y) => y - x) },
    cvssAsc: { label: 'CVSS: lowest first', compare: (a, b) => compareOptional(cvssScore(a), cvssScore(b), (x, y) => x - y) },
    titleAsc: { label: 'Title: A–Z', compare: (a, b) => compareOptional(a.title.trim() || undefined, b.title.trim() || undefined, collator.compare) },
    titleDesc: { label: 'Title: Z–A', compare: (a, b) => compareOptional(a.title.trim() || undefined, b.title.trim() || undefined, (x, y) => collator.compare(y, x)) },
    status: { label: 'Status: A–Z', compare: (a, b) => collator.compare(findingStatusLabel(a.status), findingStatusLabel(b.status)) },
    category: { label: 'Category: A–Z', compare: (a, b) => compareOptional(a.category?.trim() || undefined, b.category?.trim() || undefined, collator.compare) },
} satisfies Record<string, { label: string; compare: (a: Finding, b: Finding) => number }>;

type SortMode = keyof typeof SORT_OPTIONS;

interface SidebarProps {
    projectName: string;
    findings: Finding[];
    customStatuses?: readonly CustomFindingStatus[];
    selectedFindingId: string | null;
    activeView: 'editor' | 'settings';
    searchTerm: string;
    saveStatus?: 'saving' | 'saved';
    onSearchChange: (value: string) => void;
    onSelectFinding: (id: string) => void;
    onAddFinding: () => void;
    onOpenSettings: () => void;
    onExport: () => void;
    onBackToProjects: () => void;
    onGenerateReport: () => void;
    onBrowseTemplates: () => void;
    onDeleteFinding: (id: string) => void;
    onDuplicateFinding: (id: string) => void;
}

export default function Sidebar({
    projectName,
    findings,
    customStatuses,
    selectedFindingId,
    activeView,
    searchTerm,
    saveStatus,
    onSearchChange,
    onSelectFinding,
    onAddFinding,
    onOpenSettings,
    onExport,
    onBackToProjects,
    onGenerateReport,
    onBrowseTemplates,
    onDeleteFinding,
    onDuplicateFinding,
}: SidebarProps) {
    const [sortMode, setSortMode] = useState<SortMode>('newest');
    const [filterSeverity, setFilterSeverity] = useState<Severity | 'All'>('All');
    const [filterStatus, setFilterStatus] = useState<FindingStatus | null>(null);
    const [showFilters, setShowFilters] = useState(false);

    // Apply filters
    let filtered = findings;
    if (filterSeverity !== 'All') filtered = filtered.filter((f) => f.severity === filterSeverity);
    if (filterStatus !== null) filtered = filtered.filter((f) => f.status === filterStatus);

    // Apply sort
    const compare = SORT_OPTIONS[sortMode].compare;
    const sorted = [...filtered].sort((a, b) => compare(a, b) || SORT_OPTIONS.newest.compare(a, b));

    const activeFilters = (filterSeverity !== 'All' ? 1 : 0) + (filterStatus !== null ? 1 : 0);

    return (
        <aside className="w-80 flex flex-col bg-[#121214] border-r border-zinc-800/50 print:hidden shrink-0">
            <SidebarHeader
                projectName={projectName}
                searchTerm={searchTerm}
                saveStatus={saveStatus}
                onSearchChange={onSearchChange}
                onAddFinding={onAddFinding}
                onExport={onExport}
                onBackToProjects={onBackToProjects}
            />

            {/* Filter/Sort bar */}
            <div className="px-3 pt-2 pb-1 flex items-center gap-2">
                <button
                    onClick={() => setShowFilters(!showFilters)}
                    className={`flex items-center gap-1 text-[11px] px-2 py-1 rounded transition-colors ${showFilters || activeFilters > 0 ? 'bg-emerald-500/10 text-emerald-400' : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/40'}`}
                >
                    <Filter className="w-3 h-3" />
                    Filter
                    {activeFilters > 0 && <span className="bg-emerald-500 text-black text-[9px] font-bold w-3.5 h-3.5 rounded-full flex items-center justify-center">{activeFilters}</span>}
                </button>
                <select
                    aria-label="Sort findings"
                    value={sortMode}
                    onChange={(e) => setSortMode(e.target.value as SortMode)}
                    className="text-[11px] bg-transparent text-zinc-500 hover:text-zinc-300 outline-none cursor-pointer"
                >
                    {Object.entries(SORT_OPTIONS).map(([value, { label }]) => (
                        <option key={value} value={value}>{label}</option>
                    ))}
                </select>
                <span className="ml-auto text-[10px] text-zinc-600">{sorted.length}/{findings.length}</span>
            </div>

            {/* Filter panel */}
            {showFilters && (
                <div className="px-3 py-2 border-b border-zinc-800/50 flex flex-wrap gap-1.5">
                    {(['All', 'Critical', 'High', 'Medium', 'Low', 'Info'] as const).map((sev) => (
                        <button
                            key={sev}
                            onClick={() => setFilterSeverity(sev)}
                            className={`text-[10px] font-medium px-2 py-0.5 rounded transition-colors ${filterSeverity === sev ? 'bg-zinc-700 text-white' : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60'}`}
                        >
                            {sev}
                        </button>
                    ))}
                    <span className="w-px h-4 bg-zinc-800 self-center mx-0.5" />
                    {[null, ...findingStatusNames(customStatuses, findings.map(finding => finding.status))].map((st) => (
                        <button
                            key={st ?? ''}
                            onClick={() => setFilterStatus(st)}
                            className={`text-[10px] font-medium px-2 py-0.5 rounded transition-colors ${filterStatus === st ? 'bg-zinc-700 text-white' : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60'}`}
                        >
                            {st === null ? 'All statuses' : findingStatusLabel(st)}
                        </button>
                    ))}
                </div>
            )}

            <FindingList
                findings={sorted}
                customStatuses={customStatuses}
                selectedFindingId={selectedFindingId}
                onSelectFinding={onSelectFinding}
                onDeleteFinding={onDeleteFinding}
                onDuplicateFinding={onDuplicateFinding}
            />
            <div className="p-3 border-t border-zinc-800/50">
                <button
                    onClick={onBrowseTemplates}
                    className="w-full flex items-center text-left text-sm px-3 py-2 rounded-lg transition-colors text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200"
                >
                    <BookOpen className="w-4 h-4 mr-2" />
                    Browse Templates
                    <span className="ml-auto text-[10px] text-zinc-600">{ALL_TEMPLATES.length}</span>
                </button>
            </div>
            <div className="p-3 border-t border-zinc-800/50 bg-[#121214] space-y-1">
                <button
                    onClick={onGenerateReport}
                    className="w-full flex items-center text-left text-sm px-3 py-2 rounded-lg transition-colors text-emerald-400 hover:bg-emerald-500/10"
                >
                    <FileOutput className="w-4 h-4 mr-2" />
                    Generate Report
                </button>
                <button
                    onClick={onOpenSettings}
                    className={`w-full flex items-center text-left text-sm px-3 py-2 rounded-lg transition-colors ${activeView === 'settings'
                        ? 'bg-zinc-800/80 text-emerald-400'
                        : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
                        }`}
                >
                    <Settings className="w-4 h-4 mr-2" />
                    Project Settings
                </button>
            </div>
        </aside>
    );
}
