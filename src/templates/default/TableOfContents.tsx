import type { ReportData } from '../reportTypes';

const SEVERITY_COLOR: Record<string, string> = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#9ca3af',
};

export function TableOfContents({ data }: { data: ReportData }) {
    return (
        <div className="report-page px-16 py-16">
            <h2 className="text-3xl font-bold mb-10 pb-4 border-b-2 border-black">Table of Contents</h2>

            <div className="space-y-3 text-base">
                <TocEntry num="1" title="Executive Summary" />
                <TocEntry num="2" title="Scope" />
                <TocEntry num="3" title="Summary of Findings" />
                {data.stats.total > 0 && <TocEntry num="4" title="Detailed Findings" />}

                {/* Finding sub-entries */}
                {data.findings.map((f, i) => (
                    <div key={f.id} className="flex items-baseline gap-3 pl-8">
                        <span className="text-sm text-gray-500 shrink-0 w-12">{`4.${i + 1}`}</span>
                        <span className="w-2.5 h-2.5 rounded-sm shrink-0 relative top-[-1px]" style={{ backgroundColor: SEVERITY_COLOR[f.severity] }} />
                        <span className="flex-1 text-sm">{f.title || 'Untitled Finding'}</span>
                        <span className="text-xs text-gray-400 uppercase font-semibold">{f.severity}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}

function TocEntry({ num, title }: { num: string; title: string }) {
    return (
        <div className="flex items-baseline gap-3">
            <span className="text-gray-500 font-semibold shrink-0 w-12">{num}</span>
            <span className="font-semibold text-lg">{title}</span>
        </div>
    );
}
