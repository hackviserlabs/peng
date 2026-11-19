import { ArrowLeft, Download, Plus, Search, Check } from 'lucide-react';

interface SidebarHeaderProps {
    projectName: string;
    searchTerm: string;
    saveStatus?: 'saving' | 'saved';
    onSearchChange: (value: string) => void;
    onAddFinding: () => void;
    onExport: () => void;
    onBackToProjects: () => void;
}

export default function SidebarHeader({
    projectName,
    searchTerm,
    saveStatus,
    onSearchChange,
    onAddFinding,
    onExport,
    onBackToProjects,
}: SidebarHeaderProps) {
    return (
        <div className="p-5 border-b border-zinc-800/50">
            <div className="flex justify-between items-center mb-4">
                <button
                    onClick={onBackToProjects}
                    className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-white transition-colors"
                >
                    <ArrowLeft className="w-4 h-4" /> Projects
                </button>
                <div className="flex items-center gap-2">
                    {saveStatus === 'saving' && <span role="status" className="text-[10px] text-zinc-400">Saving…</span>}
                    {saveStatus === 'saved' && (
                        <span className="flex items-center gap-1 text-[10px] text-emerald-500/70">
                            <Check className="w-3 h-3" /> Saved
                        </span>
                    )}
                    <button
                        onClick={onExport}
                        className="p-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded transition-colors"
                        title="Export Project"
                    >
                        <Download className="w-4 h-4" />
                    </button>
                </div>
            </div>

            <h2 className="text-sm font-semibold text-white truncate mb-4" title={projectName}>
                {projectName || 'Untitled Project'}
            </h2>

            <button
                onClick={onAddFinding}
                className="w-full bg-white hover:bg-zinc-200 text-black font-medium py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition-colors mb-4"
            >
                <Plus className="w-4 h-4" /> New Finding
            </button>

            <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                <input
                    type="text"
                    placeholder="Search findings..."
                    value={searchTerm}
                    onChange={(e) => onSearchChange(e.target.value)}
                    className="w-full bg-[#09090b] border border-zinc-800 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50 transition-colors"
                />
            </div>
        </div>
    );
}
