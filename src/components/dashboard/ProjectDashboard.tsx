import { useState } from 'react';
import { Plus, Trash2, FolderOpen, Calendar, Upload, Github } from 'lucide-react';
import ConfirmModal from '../ui/ConfirmModal';
import { SEVERITY_COLORS } from '../../constants';
import type { Finding, Project } from '../../types';

interface ProjectDashboardProps {
    projects: Project[];
    getFindings: (id: string) => Finding[] | undefined;
    getFindingsError: (id: string) => string | undefined;
    onRetryFindings: (id: string) => void;
    busy: boolean;
    serverBacked: boolean;
    account?: string;
    signOutDisabled: boolean;
    onSignOut?: () => void;
    onSelectProject: (id: string) => void;
    onCreateProject: (name: string) => Promise<void>;
    onDeleteProject: (id: string) => void;
    onImport: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

export default function ProjectDashboard({
    projects,
    getFindings,
    getFindingsError,
    onRetryFindings,
    busy,
    serverBacked,
    account,
    signOutDisabled,
    onSignOut,
    onSelectProject,
    onCreateProject,
    onDeleteProject,
    onImport,
}: ProjectDashboardProps) {
    const [newName, setNewName] = useState('');
    const [showCreate, setShowCreate] = useState(false);
    const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
    const pendingProject = projects.find(p => p.id === pendingDeleteId);

    const handleCreate = async () => {
        const name = newName.trim();
        if (!name || busy) return;
        await onCreateProject(name);
    };

    return (
        <>
            <div className="flex min-h-0 flex-1 bg-[#09090b] text-zinc-300 font-sans selection:bg-emerald-500/30">
                <div className="flex-1 overflow-y-auto">
                    <div className="max-w-5xl mx-auto px-8 py-16">

                        {/* Header */}
                        <div className="flex items-center justify-between mb-12">
                            <div className="flex items-center gap-3">
                                <img src="/logo.svg" alt="peng" className="w-9 h-9" style={{ filter: 'drop-shadow(0 0 1px rgba(161,161,170,0.4))' }} />
                                <h1 className="text-3xl font-bold text-white tracking-tight">peng</h1>
                            </div>
                            <div className="flex items-center gap-3">
                                <a href="https://github.com/hackviserr/peng" target="_blank" rel="noopener noreferrer"
                                    className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-zinc-300 bg-zinc-800/50 hover:bg-zinc-700 rounded-lg transition-colors border border-zinc-700/50">
                                    <Github className="w-4 h-4" /> GitHub
                                </a>
                                <label className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-zinc-300 bg-zinc-800/50 hover:bg-zinc-700 rounded-lg transition-colors border border-zinc-700/50 cursor-pointer focus-within:ring-2 focus-within:ring-emerald-400">
                                    <Upload className="w-4 h-4" /> Import
                                    <input type="file" accept=".json" onChange={onImport} disabled={busy} className="sr-only" />
                                </label>
                                <button
                                    onClick={() => setShowCreate(true)} disabled={busy}
                                    className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
                                >
                                    <Plus className="w-4 h-4" /> New Project
                                </button>
                            </div>
                        </div>

                        {account && (
                            <div className="mb-4 flex items-center justify-between text-sm text-zinc-400">
                                <span>Connected workspace · {account}</span>
                                <button onClick={onSignOut} disabled={signOutDisabled}
                                    className="rounded-md border border-zinc-700 px-3 py-2 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50">
                                    Sign out
                                </button>
                            </div>
                        )}

                        {/* Hero Description */}
                        <div className="mb-10 pb-10 border-b border-zinc-800/60">
                            <p className="text-lg text-zinc-400 mb-2">
                                Open-source penetration test report writing tool. Write, manage, and export professional pentest reports — fast.
                            </p>
                            <p className="text-sm text-zinc-600 mb-6">
                                {serverBacked
                                    ? 'Projects and findings are stored on the server. Import uploads the selected file to this workspace.'
                                    : 'Local workspace · Projects and findings are stored in this browser.'}
                            </p>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {[
                                    { title: 'Template Library', desc: '45+ finding templates with real-world descriptions' },
                                    { title: 'Rich Text Editor', desc: 'Full WYSIWYG editor with images and formatting' },
                                    { title: 'Report Export', desc: 'Print-ready reports and JSON data export' },
                                    { title: 'Multi-Project', desc: 'Manage multiple assessments independently' },
                                ].map((f) => (
                                    <div key={f.title} className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800/50">
                                        <div className="text-xs font-semibold text-zinc-300 mb-0.5">{f.title}</div>
                                        <div className="text-[11px] text-zinc-600 leading-snug">{f.desc}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Create Project Inline */}
                        {showCreate && (
                            <div className="mb-8 p-5 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-center gap-4">
                                <input
                                    type="text"
                                    autoFocus
                                    value={newName}
                                    onChange={(e) => setNewName(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                                    placeholder="Project name (e.g. Acme Corp Q1 2026 Pentest)"
                                    className="flex-1 bg-transparent border border-zinc-700 rounded-lg px-4 py-2.5 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-zinc-600"
                                />
                                <button onClick={handleCreate} disabled={busy} className="px-4 py-2.5 text-sm font-medium text-black bg-emerald-500 hover:bg-emerald-400 rounded-lg transition-colors">Create</button>
                                <button onClick={() => { setShowCreate(false); setNewName(''); }} className="px-4 py-2.5 text-sm font-medium text-zinc-400 hover:text-white transition-colors">Cancel</button>
                            </div>
                        )}

                        {/* Project List */}
                        {projects.length === 0 && !showCreate ? (
                            <div className="flex flex-col items-center justify-center py-32 text-zinc-500">
                                <div className="w-20 h-20 mb-6 rounded-2xl bg-zinc-800/50 flex items-center justify-center border border-zinc-800">
                                    <FolderOpen className="w-10 h-10 text-zinc-400" />
                                </div>
                                <h2 className="text-xl font-medium text-zinc-300 mb-2">No Projects Yet</h2>
                                <p className="text-sm mb-6">Create your first pentest project to get started.</p>
                                <button
                                    onClick={() => setShowCreate(true)} disabled={busy}
                                    className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
                                >
                                    <Plus className="w-4 h-4" /> New Project
                                </button>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {projects.map((project) => {
                                    const findings = getFindings(project.id) ?? [];
                                    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
                                    for (const finding of findings) counts[finding.severity]++;
                                    const findingsError = getFindingsError(project.id);
                                    return (
                                        <div
                                            key={project.id}
                                            onClick={() => { if (!busy) onSelectProject(project.id); }}
                                            className="group relative p-5 rounded-xl bg-zinc-900/50 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/30 cursor-pointer transition-all"
                                        >
                                            {/* Delete */}
                                            <button
                                                onClick={(e) => { e.stopPropagation(); setPendingDeleteId(project.id); }}
                                                className="absolute top-4 right-4 p-1.5 text-zinc-600 hover:text-red-400 hover:bg-red-400/10 rounded-md transition-colors opacity-0 group-hover:opacity-100"
                                                title="Delete Project"
                                                disabled={busy}
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>

                                            <h3 className="text-lg font-semibold text-white mb-1 pr-8 truncate">{project.name || 'Untitled Project'}</h3>
                                            {project.clientName && <p className="text-sm text-zinc-400 mb-3 truncate">{project.clientName}</p>}

                                            {findingsError && (
                                                <button title={findingsError} className="mb-2 text-xs text-red-300 underline"
                                                    onClick={(event) => { event.stopPropagation(); onRetryFindings(project.id); }}>
                                                    Retry finding count
                                                </button>
                                            )}

                                            {/* Severity badges */}
                                            {findings.length > 0 && (
                                                <div className="flex items-center gap-1.5 mb-3">
                                                    {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map((sev) =>
                                                        counts[sev] > 0 ? (
                                                            <span key={sev} className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${SEVERITY_COLORS[sev].bg} ${SEVERITY_COLORS[sev].text}`}>
                                                                {counts[sev]} {sev.charAt(0)}
                                                            </span>
                                                        ) : null
                                                    )}
                                                    <span className="text-[10px] text-zinc-500 ml-1">{findings.length} findings</span>
                                                </div>
                                            )}

                                            {/* Meta row */}
                                            <div className="flex items-center gap-4 text-xs text-zinc-500">
                                                {project.assessmentDateStart && (
                                                    <span className="flex items-center gap-1"><Calendar className="w-3 h-3" />{project.assessmentDateStart}</span>
                                                )}
                                                <span>v{project.reportVersion}</span>
                                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${project.classification === 'Confidential' ? 'bg-red-500/10 text-red-400'
                                                    : project.classification === 'Internal' ? 'bg-yellow-500/10 text-yellow-400'
                                                        : 'bg-green-500/10 text-green-400'
                                                    }`}>{project.classification}</span>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>
            </div>
            <ConfirmModal
                open={!!pendingDeleteId}
                title="Delete Project"
                message={`"${pendingProject?.name || ''}" and all its findings will be permanently deleted.`}
                confirmLabel="Delete Project"
                onConfirm={() => { if (pendingDeleteId) onDeleteProject(pendingDeleteId); setPendingDeleteId(null); }}
                onCancel={() => setPendingDeleteId(null)}
            />
        </>
    );
}
