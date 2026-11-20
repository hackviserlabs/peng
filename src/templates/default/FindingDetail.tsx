import { sanitizeRichText } from '../../lib/richText';
import { findingStatusLabel } from '../../types';
import type { ReactNode } from 'react';
import type { ReportFinding } from '../reportTypes';

interface FindingDetailProps {
    finding: ReportFinding;
    index: number;
}

export function FindingDetail({ finding, index }: FindingDetailProps) {
    const f = finding;

    return (
        <div className="report-page px-16 py-16">
            {/* Finding Header */}
            <div className="mb-8 pb-4 border-b-2 border-black">
                <div className="flex items-baseline justify-between">
                    <h3 className="text-2xl font-bold">
                        <span className="text-gray-400 mr-2">4.{index + 1}</span>
                        {f.title || 'Untitled Finding'}
                    </h3>
                    <span className={`text-sm font-bold uppercase px-3 py-1 rounded ${f.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                        f.severity === 'High' ? 'bg-orange-100 text-orange-700' :
                            f.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                                f.severity === 'Low' ? 'bg-blue-100 text-blue-700' :
                                    'bg-gray-100 text-gray-600'
                        }`}>
                        {f.severity}
                    </span>
                </div>
            </div>

            {/* Metadata Table */}
            <table className="text-sm w-full mb-8 border-collapse">
                <tbody>
                    <MetaRow label="Severity" value={f.severity} />
                    <MetaRow label="Status" value={findingStatusLabel(f.status)} />
                    {f.confidence && <MetaRow label="Confidence" value={f.confidence} />}
                    {f.category && <MetaRow label="Category" value={f.category} />}
                    {f.templateId && <MetaRow label="Template ID" value={f.templateId} />}
                    {!!f.tags?.length && (
                        <MetaRow label="Tags" value={
                            <ul className="flex flex-wrap gap-1">
                                {f.tags.map((tag, index) => (
                                    <li key={index} className="rounded bg-gray-100 px-2 py-0.5">{tag}</li>
                                ))}
                            </ul>
                        } />
                    )}
                    {f.cvss && <MetaRow label="CVSS Score" value={f.cvss} />}
                    {f.cvssVector && <MetaRow label="CVSS Vector" value={f.cvssVector} />}
                    {f.cve && <MetaRow label="CVE" value={f.cve} />}
                    {f.cwe && <MetaRow label="CWE" value={f.cwe} />}
                    {(f.url || f.method) && <MetaRow label="Endpoint" value={`${f.method ? f.method + ' ' : ''}${f.url}`} />}
                    {f.parameter && <MetaRow label="Parameter" value={f.parameter} />}
                    {f.affectedHost && <MetaRow label="Affected Host" value={f.affectedHost} />}
                    {f.port && <MetaRow label="Port" value={f.port} />}
                </tbody>
            </table>

            {/* Content Sections */}
            <div className="space-y-8">
                {!!f.targets?.length && (
                    <section>
                        <h4 className="text-lg font-bold mb-3 text-gray-800">Targets</h4>
                        <ol className="list-decimal pl-5 space-y-3 text-sm">
                            {f.targets.map((target, index) => (
                                <li key={index} className="report-no-break">
                                    <div className="whitespace-pre-wrap wrap-anywhere font-mono">{target.url || 'URL unspecified'}</div>
                                    <dl className="text-gray-600 whitespace-pre-wrap wrap-anywhere">
                                        {target.method && <div><dt className="inline font-semibold">Method </dt><dd className="inline">{target.method}</dd></div>}
                                        {target.parameter && <div><dt className="inline font-semibold">Parameter </dt><dd className="inline">{target.parameter}</dd></div>}
                                        {target.host && <div><dt className="inline font-semibold">Host </dt><dd className="inline">{target.host}</dd></div>}
                                        {target.port && <div><dt className="inline font-semibold">Port </dt><dd className="inline">{target.port}</dd></div>}
                                    </dl>
                                </li>
                            ))}
                        </ol>
                    </section>
                )}
                {!!f.evidence?.length && (
                    <section>
                        <h4 className="text-lg font-bold mb-3 text-gray-800">Evidence references</h4>
                        <ul className="list-disc pl-5 space-y-1 text-sm font-mono whitespace-pre-wrap wrap-anywhere">
                            {f.evidence.map((reference, index) => <li key={index}>{reference}</li>)}
                        </ul>
                    </section>
                )}
                {f.description && <ContentSection title="Description" html={f.description} />}
                {f.poc && <ContentSection title="Proof of Concept" html={f.poc} />}
                {f.requestResponse && <ContentSection title="Request / Response" html={f.requestResponse} />}
                {f.impact && <ContentSection title="Impact" html={f.impact} />}
                {f.remediation && <ContentSection title="Remediation" html={f.remediation} />}
                {f.references && <ContentSection title="References" html={f.references} />}
            </div>
        </div>
    );
}

function MetaRow({ label, value }: { label: string; value: ReactNode }) {
    return (
        <tr className="border-b border-gray-100">
            <td className="py-1.5 pr-6 font-semibold text-gray-600 w-40">{label}</td>
            <td className="py-1.5 whitespace-pre-wrap wrap-anywhere">{value}</td>
        </tr>
    );
}

function ContentSection({ title, html }: { title: string; html: string }) {
    return (
        <div className="report-no-break">
            <h4 className="text-lg font-bold mb-3 text-gray-800">{title}</h4>
            <div className="prose report-prose max-w-none text-sm leading-relaxed" dangerouslySetInnerHTML={{ __html: sanitizeRichText(html) }} />
        </div>
    );
}
