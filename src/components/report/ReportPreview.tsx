import { useState, useRef } from 'react';
import { X, Printer, ChevronDown } from 'lucide-react';
import { listTemplates } from '../../templates/registry';
import { buildReportData } from '../../templates/reportTypes';
import type { Project, Finding } from '../../types';

interface ReportPreviewProps {
    project: Project;
    findings: Finding[];
    onClose: () => void;
}

export default function ReportPreview({ project, findings, onClose }: ReportPreviewProps) {
    const templates = listTemplates();
    const [selectedId, setSelectedId] = useState(templates[0]?.id ?? '');
    const reportRef = useRef<HTMLDivElement>(null);

    const template = templates.find((t) => t.id === selectedId) ?? templates[0];
    const data = buildReportData(project, findings);
    const TemplateComponent = template.component;

    const handlePrint = () => {
        document.body.classList.add('report-printing');
        window.print();
        document.body.classList.remove('report-printing');
    };

    return (
        <div className="fixed inset-0 z-[100] flex flex-col bg-zinc-950">
            {/* Toolbar */}
            <div className="flex items-center justify-between px-6 py-3 bg-zinc-900 border-b border-zinc-800 shrink-0 report-toolbar">
                <div className="flex items-center gap-4">
                    <h2 className="text-sm font-semibold text-white">Report Preview</h2>
                    {templates.length > 1 && (
                        <div className="relative">
                            <select
                                value={selectedId}
                                onChange={(e) => setSelectedId(e.target.value)}
                                className="text-xs bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-md px-3 py-1.5 outline-none cursor-pointer appearance-none pr-7"
                            >
                                {templates.map((t) => (
                                    <option key={t.id} value={t.id}>{t.name}</option>
                                ))}
                            </select>
                            <ChevronDown className="w-3 h-3 absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
                        </div>
                    )}
                    <span className="text-xs text-zinc-500">
                        {data.stats.total} findings · {template.name}
                    </span>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={handlePrint}
                        className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
                    >
                        <Printer className="w-4 h-4" />
                        Print / Save as PDF
                    </button>
                    <button
                        onClick={onClose}
                        aria-label="Close report preview"
                        className="p-2 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg transition-colors"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>
            </div>

            {/* Report Content */}
            <div className="flex-1 overflow-y-auto bg-zinc-800/30">
                <div
                    ref={reportRef}
                    id="report-content"
                    className="report-preview max-w-[210mm] mx-auto my-8 bg-white text-black shadow-2xl"
                >
                    <TemplateComponent data={data} />
                </div>
            </div>
        </div>
    );
}
