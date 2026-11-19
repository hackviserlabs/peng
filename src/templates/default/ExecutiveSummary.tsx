import { sanitizeRichText } from '../../lib/richText';
import type { ReportData } from '../reportTypes';
import type { Severity } from '../../types';

const SEV_COLORS: Record<Severity, string> = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#9ca3af',
};

export function ExecutiveSummary({ data }: { data: ReportData }) {
    const { project, stats } = data;

    return (
        <div className="report-page px-16 py-16">
            <h2 className="text-3xl font-bold mb-8 pb-4 border-b-2 border-black">1. Executive Summary</h2>

            {/* Summary HTML */}
            {project.executiveSummary ? (
                <div className="prose max-w-none mb-10 text-base leading-relaxed" dangerouslySetInnerHTML={{ __html: sanitizeRichText(project.executiveSummary) }} />
            ) : (
                <p className="text-gray-400 italic mb-10">No executive summary provided.</p>
            )}

            {/* Severity Distribution Table */}
            <h3 className="text-xl font-bold mb-4">Finding Distribution</h3>
            <table className="w-full border-collapse text-sm mb-6">
                <thead>
                    <tr className="border-b-2 border-black">
                        <th className="text-left py-2 font-bold">Severity</th>
                        <th className="text-center py-2 font-bold w-20">Count</th>
                        <th className="text-left py-2 font-bold pl-4">Distribution</th>
                    </tr>
                </thead>
                <tbody>
                    {(['Critical', 'High', 'Medium', 'Low', 'Info'] as Severity[]).map((sev) => {
                        const count = stats.bySeverity[sev];
                        const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
                        return (
                            <tr key={sev} className="border-b border-gray-200">
                                <td className="py-2 font-semibold flex items-center gap-2">
                                    <span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor: SEV_COLORS[sev] }} />
                                    {sev}
                                </td>
                                <td className="py-2 text-center font-bold text-lg">{count}</td>
                                <td className="py-2 pl-4">
                                    <div className="w-full bg-gray-100 rounded-full h-4 overflow-hidden">
                                        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[sev] }} />
                                    </div>
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
                <tfoot>
                    <tr className="border-t-2 border-black">
                        <td className="py-2 font-bold">Total</td>
                        <td className="py-2 text-center font-bold text-lg">{stats.total}</td>
                        <td />
                    </tr>
                </tfoot>
            </table>

            {/* Status breakdown */}
            <div className="flex gap-8 text-sm">
                {Object.entries(stats.byStatus).map(([status, count]) => (
                    <div key={status}>
                        <span className="text-gray-500">{status}: </span>
                        <span className="font-bold">{count}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}
