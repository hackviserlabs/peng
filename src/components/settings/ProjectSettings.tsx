import type { DeploymentMode } from '../../lib/api';
import LocalMcpAccess from './LocalMcpAccess';
import ProjectMcpKeys from './ProjectMcpKeys';
import { Settings, FileText, Users, Calendar, Shield, Bookmark } from 'lucide-react';
import RichTextEditor from '../editor/RichTextEditor';
import ProjectFindingStatuses from './ProjectFindingStatuses';
import ScopeList from './ScopeList';
import type { Project, Classification } from '../../types';
import { TEMPLATE_INSTRUCTIONS_LIMIT } from '../../constants';

interface ProjectSettingsProps {
    project: Project;
    mode?: DeploymentMode;
    onUpdate: <K extends keyof Project>(field: K, value: Project[K]) => void;
}

export default function ProjectSettings({ project, mode, onUpdate }: ProjectSettingsProps) {
    return (
        <main className="flex-1 flex flex-col min-w-0 bg-[#09090b] relative print:bg-white print:text-black">
            <div className="flex-1 overflow-y-auto print:overflow-visible">
                <div className="max-w-4xl mx-auto px-12 py-16 print:p-0 print:max-w-none">

                    {/* Page Title */}
                    <div className="mb-12 print:mb-6">
                        <h1 className="text-4xl font-bold text-white print:text-black flex items-center gap-3 mb-2">
                            <Settings className="w-8 h-8 text-emerald-500 print:hidden" />
                            Project Settings
                        </h1>
                        <p className="text-zinc-500 text-sm print:hidden">
                            General report information and executive summary.
                        </p>
                    </div>

                    {/* Form Grid */}
                    <div className="space-y-10">

                        {/* Row: Project Name */}
                        <div>
                            <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                <FileText className="w-4 h-4" /> Project Name
                            </label>
                            <input
                                type="text"
                                value={project.name}
                                onChange={(e) => onUpdate('name', e.target.value)}
                                placeholder="e.g. Acme Corp Web Application Penetration Test"
                                className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-zinc-600"
                            />
                        </div>

                        {/* Two-column grid */}
                        <div className="grid grid-cols-2 gap-6">
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Users className="w-4 h-4" /> Client Name
                                </label>
                                <input
                                    type="text"
                                    value={project.clientName}
                                    onChange={(e) => onUpdate('clientName', e.target.value)}
                                    placeholder="e.g. Acme Corporation"
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-zinc-600"
                                />
                            </div>
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Shield className="w-4 h-4" /> Assessor / Firm
                                </label>
                                <input
                                    type="text"
                                    value={project.assessorName}
                                    onChange={(e) => onUpdate('assessorName', e.target.value)}
                                    placeholder="e.g. John Doe / SecureTech Inc."
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-zinc-600"
                                />
                            </div>
                        </div>

                        {/* Dates Row */}
                        <div className="grid grid-cols-3 gap-6">
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Calendar className="w-4 h-4" /> Assessment Start
                                </label>
                                <input
                                    type="date"
                                    value={project.assessmentDateStart}
                                    onChange={(e) => onUpdate('assessmentDateStart', e.target.value)}
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors [color-scheme:dark]"
                                />
                            </div>
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Calendar className="w-4 h-4" /> Assessment End
                                </label>
                                <input
                                    type="date"
                                    value={project.assessmentDateEnd}
                                    onChange={(e) => onUpdate('assessmentDateEnd', e.target.value)}
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors [color-scheme:dark]"
                                />
                            </div>
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Calendar className="w-4 h-4" /> Report Date
                                </label>
                                <input
                                    type="date"
                                    value={project.reportDate}
                                    onChange={(e) => onUpdate('reportDate', e.target.value)}
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors [color-scheme:dark]"
                                />
                            </div>
                        </div>

                        {/* Version & Classification */}
                        <div className="grid grid-cols-2 gap-6">
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Bookmark className="w-4 h-4" /> Report Version
                                </label>
                                <input
                                    type="text"
                                    value={project.reportVersion}
                                    onChange={(e) => onUpdate('reportVersion', e.target.value)}
                                    placeholder="e.g. 1.0"
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-zinc-600"
                                />
                            </div>
                            <div>
                                <label className="flex items-center gap-2 text-sm font-medium text-zinc-400 mb-2">
                                    <Shield className="w-4 h-4" /> Classification
                                </label>
                                <select
                                    value={project.classification}
                                    onChange={(e) => onUpdate('classification', e.target.value as Classification)}
                                    className="w-full bg-zinc-900/50 border border-zinc-800 rounded-lg px-4 py-3 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors appearance-none cursor-pointer"
                                >
                                    <option value="Confidential" className="bg-zinc-900">Confidential</option>
                                    <option value="Internal" className="bg-zinc-900">Internal</option>
                                    <option value="Public" className="bg-zinc-900">Public</option>
                                </select>
                            </div>
                        </div>

                        <div className="border-t border-zinc-800/50" />

                        <ProjectFindingStatuses
                            statuses={project.customFindingStatuses}
                            onChange={(statuses) => onUpdate('customFindingStatuses', statuses)}
                        />

                        {/* Scope */}
                        <div>
                            <h3 className="flex items-center text-lg font-semibold text-zinc-100 print:text-black mb-3">
                                <Shield className="w-5 h-5 mr-2 text-blue-400/70 print:hidden" /> Scope
                            </h3>
                            <ScopeList
                                value={project.scope}
                                onChange={(value) => onUpdate('scope', value)}
                            />
                        </div>

                        {/* Executive Summary */}
                        <div>
                            <h3 className="flex items-center text-lg font-semibold text-zinc-100 print:text-black mb-3">
                                <FileText className="w-5 h-5 mr-2 text-emerald-400/70 print:hidden" /> Executive Summary
                            </h3>
                            <RichTextEditor
                                content={project.executiveSummary}
                                placeholder="High-level overview of the assessment for non-technical stakeholders (C-level executives)..."
                                onChange={(value) => onUpdate('executiveSummary', value)}
                            />
                        </div>

                        {mode && (
                            <>
                                <label className="block space-y-2">
                                    <span className="block text-lg font-semibold text-zinc-100">Template instructions</span>
                                    <span className="block text-sm text-zinc-400">Project guidance for agents writing findings.</span>
                                    <textarea
                                        rows={5}
                                        maxLength={TEMPLATE_INSTRUCTIONS_LIMIT}
                                        value={project.templateInstructions ?? ''}
                                        onChange={(event) => onUpdate('templateInstructions', event.target.value)}
                                        className="w-full rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-sm text-zinc-200 focus:border-emerald-500/50 focus:outline-none"
                                    />
                                </label>
                                {mode === 'local'
                                    ? <LocalMcpAccess />
                                    : <ProjectMcpKeys key={project.id} projectId={project.id} />}
                            </>
                        )}

                    </div>
                </div>
            </div>
        </main>
    );
}
