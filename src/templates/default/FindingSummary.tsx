import type { ReportData } from '../reportTypes';
import { findingStatusLabel, type Severity } from '../../types';

const SEV_COLORS: Record<Severity, string> = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#9ca3af',
};

export function FindingSummary({ data }: { data: ReportData }) {
    return (
        <div className="report-page px-16 py-16">
            <h2 className="text-3xl font-bold mb-8 pb-4 border-b-2 border-black">3. Summary of Findings</h2>

            <table className="w-full border-collapse text-sm">
                <thead>
                    <tr className="border-b-2 border-black">
                        <th className="text-left py-2 font-bold w-10">#</th>
                        <th className="text-left py-2 font-bold">Finding Title</th>
                        <th className="text-center py-2 font-bold w-24">Severity</th>
                        <th className="text-center py-2 font-bold w-24">Status</th>
                        <th className="text-center py-2 font-bold w-16">CVSS</th>
                    </tr>
                </thead>
                <tbody>
                    {data.findings.map((f, i) => (
                        <tr key={f.id} className="border-b border-gray-200">
                            <td className="py-2 text-gray-500">{i + 1}</td>
                            <td className="py-2 pr-2 wrap-anywhere">
                                <div className="font-medium">{f.title || 'Untitled'}</div>
                                {f.category && <div className="text-xs text-gray-600">{f.category}</div>}
                                {f.confidence && <div className="text-xs text-gray-600">{f.confidence} confidence</div>}
                            </td>
                            <td className="py-2 text-center">
                                <span className="inline-flex items-center gap-1.5 text-xs font-bold uppercase">
                                    <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ backgroundColor: SEV_COLORS[f.severity] }} />
                                    {f.severity}
                                </span>
                            </td>
                            <td className="py-2 text-center text-xs">{findingStatusLabel(f.status)}</td>
                            <td className="py-2 text-center font-mono text-xs">{f.cvss || '—'}</td>
                        </tr>
                    ))}
                </tbody>
            </table>

            {data.findings.length === 0 && (
                <p className="text-gray-400 italic mt-6">No findings recorded.</p>
            )}
        </div>
    );
}
