import { useState, useRef, useEffect } from 'react';
import { Activity, CircleDot, Link2, Tag, Server, Hash, ShieldAlert, List, BarChart3, Plus } from 'lucide-react';
import { findingStatusAppearance, SEVERITY_COLORS } from '../../constants';
import { autoResize } from '../../hooks/useAutoResize';
import { findingStatusLabel, type Finding, type Severity, type UpdateFindingField } from '../../types';

import { findingStatusNames, type CustomFindingStatus } from '../../types/findingStatus';

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

// All optional properties
const OPTIONAL_PROPERTIES = [
    { key: 'url', label: 'Endpoint', icon: Link2, desc: 'HTTP method and URL path of the affected endpoint' },
    { key: 'parameter', label: 'Parameter', icon: Tag, desc: 'Vulnerable request parameter name' },
    { key: 'affectedHost', label: 'Host', icon: Server, desc: 'IP address or hostname of the affected system' },
    { key: 'port', label: 'Port', icon: Hash, desc: 'Network port number of the affected service' },
    { key: 'cve', label: 'CVE', icon: ShieldAlert, desc: 'CVE identifier (e.g. CVE-2024-1234)' },
    { key: 'cwe', label: 'CWE', icon: List, desc: 'Common Weakness Enumeration ID' },
    { key: 'cvss', label: 'CVSS', icon: BarChart3, desc: 'CVSS v3.1 base score (0.0 – 10.0)' },
] as const;

type OptionalKey = typeof OPTIONAL_PROPERTIES[number]['key'];

function useDropdown() {
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement>(null);
    useEffect(() => {
        function handleClick(e: MouseEvent) {
            if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
        }
        if (open) document.addEventListener('mousedown', handleClick);
        return () => document.removeEventListener('mousedown', handleClick);
    }, [open]);
    return { open, setOpen, ref };
}



function getCvssLabel(value: string): string {
    const n = parseFloat(value);
    if (isNaN(n)) return '';
    if (n === 0) return 'Info';
    if (n >= 9) return 'Critical';
    if (n >= 7) return 'High';
    if (n >= 4) return 'Medium';
    return 'Low';
}

interface FindingTitleProps {
    finding: Finding;
    customStatuses?: readonly CustomFindingStatus[];
    onUpdate: UpdateFindingField;
    onOpenCvssCalculator?: () => void;
}

export default function FindingTitle({ finding, customStatuses, onUpdate, onOpenCvssCalculator }: FindingTitleProps) {
    const statusAppearance = findingStatusAppearance(finding.status, customStatuses);
    const { ref: severityRef, open: severityOpen, setOpen: setSeverityOpen } = useDropdown();
    const { ref: addRef, open: addOpen, setOpen: setAddOpen } = useDropdown();
    const { ref: methodRef, open: methodOpen, setOpen: setMethodOpen } = useDropdown();
    const [visibleProps, setVisibleProps] = useState<Set<OptionalKey>>(() => {
        // Auto-show any property that already has a value
        const initial = new Set<OptionalKey>();
        for (const prop of OPTIONAL_PROPERTIES) {
            if (finding[prop.key] || (prop.key === 'url' && finding.method)
                || (prop.key === 'cvss' && finding.cvssVector)) initial.add(prop.key);
        }
        return initial;
    });

    const isVisible = (key: OptionalKey) => visibleProps.has(key) || Boolean(finding[key])
        || (key === 'url' && Boolean(finding.method)) || (key === 'cvss' && Boolean(finding.cvssVector));
    const hiddenProps = OPTIONAL_PROPERTIES.filter(({ key }) => !isVisible(key));

    const addProperty = (key: OptionalKey) => {
        setVisibleProps((prev) => new Set(prev).add(key));
        setAddOpen(false);
    };

    const removeProperty = (key: OptionalKey) => {
        onUpdate(key, '');
        if (key === 'cvss') onUpdate('cvssVector', '');
        setVisibleProps((prev) => {
            const next = new Set(prev);
            next.delete(key);
            return next;
        });
    };

    return (
        <div className="mb-10 print:mb-6">
            {/* Title */}
            <textarea
                value={finding.title}
                onChange={(e) => { onUpdate('title', e.target.value); autoResize(e); }}
                placeholder="Untitled"
                className="w-full bg-transparent text-4xl font-bold text-white print:text-black placeholder-zinc-600 border-none outline-none resize-none overflow-hidden block py-1 mb-1 leading-tight"
                rows={1}
                onFocus={autoResize}
            />

            {/* Property Table */}
            <div className="mt-3 print:hidden space-y-0">

                {/* Severity — always visible */}
                <div className="flex items-center group min-h-[34px] -mx-2 rounded-md hover:bg-zinc-800/40 transition-colors">
                    <div className="flex items-center gap-1.5 text-xs text-zinc-500 w-28 px-2 shrink-0">
                        <Activity className="w-3.5 h-3.5" /><span>Risk Level</span>
                    </div>
                    <div className="relative" ref={severityRef}>
                        <button onClick={() => setSeverityOpen(!severityOpen)}
                            className={`flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded transition-colors hover:bg-zinc-700/50 ${SEVERITY_COLORS[finding.severity].text}`}>
                            <span className={`w-2 h-2 rounded-sm ${SEVERITY_COLORS[finding.severity].dot}`} />
                            {finding.severity}
                        </button>
                        {severityOpen && (
                            <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-[150px]">
                                <div className="px-2.5 py-1.5 text-[10px] text-zinc-500 uppercase tracking-wider font-semibold">Select severity</div>
                                {SEVERITIES.map((s) => (
                                    <button key={s} onClick={() => { onUpdate('severity', s); setSeverityOpen(false); }}
                                        className={`w-full flex items-center gap-2 text-left text-xs px-2.5 py-1.5 transition-colors rounded-sm mx-0.5 ${s === finding.severity ? 'bg-zinc-800' : 'hover:bg-zinc-800/60'}`}
                                        style={{ width: 'calc(100% - 4px)' }}>
                                        <span className={`w-2 h-2 rounded-sm ${SEVERITY_COLORS[s].dot}`} />
                                        <span className={`font-medium ${SEVERITY_COLORS[s].text}`}>{s}</span>
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                    {finding.cvss && getCvssLabel(finding.cvss) && getCvssLabel(finding.cvss) !== finding.severity && (
                        <span className="text-[10px] text-amber-400/80 ml-1">⚠ CVSS suggests {getCvssLabel(finding.cvss)}</span>
                    )}
                </div>

                <label className="flex items-center min-h-[34px] -mx-2 rounded-md hover:bg-zinc-800/40">
                    <span className="flex items-center gap-1.5 text-xs text-zinc-500 w-28 px-2 shrink-0">
                        <CircleDot className="w-3.5 h-3.5" /><span>Status</span>
                    </span>
                    <select
                        value={finding.status}
                        onChange={(event) => onUpdate('status', event.target.value)}
                        className={`min-w-0 max-w-full truncate px-2 py-1 rounded text-xs font-medium ${statusAppearance.className}`}
                        style={statusAppearance.style}
                    >
                        {findingStatusNames(customStatuses, [finding.status]).map(status => (
                            <option key={status} value={status} className="bg-zinc-900 text-zinc-200">
                                {findingStatusLabel(status)}
                            </option>
                        ))}
                    </select>
                </label>

                {/* Optional properties — only shown when added */}
                {OPTIONAL_PROPERTIES.filter(({ key }) => isVisible(key)).map((prop) => {
                    const Icon = prop.icon;

                    // Endpoint — method dropdown + url input inline
                    if (prop.key === 'url') {
                        const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
                        return (
                            <div key={prop.key} className="flex items-center group min-h-[34px] -mx-2 rounded-md hover:bg-zinc-800/40 transition-colors">
                                <div className="flex items-center gap-1.5 text-xs text-zinc-500 w-28 px-2 shrink-0">
                                    <Icon className="w-3.5 h-3.5" /><span>{prop.label}</span>
                                </div>
                                <div className="flex items-center gap-0 flex-1">
                                    <div className="relative" ref={methodRef}>
                                        <button onClick={() => setMethodOpen(!methodOpen)}
                                            className={`text-[11px] font-mono font-semibold px-2 py-1 rounded transition-colors hover:bg-zinc-700/50 ${finding.method ? 'text-zinc-300' : 'text-zinc-600'}`}>
                                            {finding.method || '---'}
                                        </button>
                                        {methodOpen && (
                                            <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-[100px]">
                                                {METHODS.map((m) => (
                                                    <button key={m} onClick={() => { onUpdate('method', m); setMethodOpen(false); }}
                                                        className={`w-full text-left text-[11px] px-2.5 py-1.5 font-mono font-semibold transition-colors ${m === finding.method ? 'bg-zinc-800 text-zinc-200' : 'text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-300'}`}>
                                                        {m}
                                                    </button>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <input
                                        type="text"
                                        value={finding.url}
                                        onChange={(e) => onUpdate('url', e.target.value)}
                                        placeholder="/api/endpoint"
                                        className="flex-1 bg-transparent text-xs text-zinc-300 placeholder-zinc-600 outline-none px-2 py-1 rounded hover:bg-zinc-700/30 focus:bg-zinc-700/30 transition-colors"
                                    />
                                </div>
                                <button onClick={() => { removeProperty(prop.key); onUpdate('method', ''); }} className="p-1 text-zinc-600 hover:text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity mr-1" title="Remove">×</button>
                            </div>
                        );
                    }

                    if (prop.key === 'cvss') {
                        return (
                            <div key={prop.key} className="flex items-center group min-h-[34px] -mx-2 rounded-md hover:bg-zinc-800/40 transition-colors">
                                <div className="flex items-center gap-1.5 text-xs text-zinc-500 w-28 px-2 shrink-0">
                                    <Icon className="w-3.5 h-3.5" /><span>{prop.label}</span>
                                </div>
                                <div className="flex items-center gap-2 flex-1">
                                    <input
                                        type="text"
                                        value={finding.cvss}
                                        onChange={(e) => {
                                            const v = e.target.value;
                                            if (v === '' || /^\d{0,2}\.?\d{0,1}$/.test(v)) {
                                                const n = parseFloat(v);
                                                if (v === '' || (n >= 0 && n <= 10)) {
                                                    onUpdate('cvss', v);
                                                    if (finding.cvssVector && (v === '' || n !== parseFloat(finding.cvss))) {
                                                        onUpdate('cvssVector', '');
                                                    }
                                                }
                                            }
                                        }}
                                        placeholder="0.0"
                                        className="w-16 bg-transparent text-xs text-zinc-300 placeholder-zinc-600 outline-none px-2 py-1 rounded hover:bg-zinc-700/30 focus:bg-zinc-700/30 transition-colors"
                                    />
                                    {onOpenCvssCalculator && (
                                        <button
                                            type="button"
                                            onClick={onOpenCvssCalculator}
                                            className="text-[11px] px-2 py-1 rounded-md border border-zinc-700 text-zinc-300 hover:bg-zinc-800/60 hover:border-zinc-500 transition-colors"
                                        >
                                            Calculate
                                        </button>
                                    )}
                                </div>
                                <button onClick={() => removeProperty(prop.key)} className="p-1 text-zinc-600 hover:text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity mr-1" title="Remove CVSS score and vector">×</button>
                            </div>
                        );
                    }

                    // Default — inline text input
                    return (
                        <div key={prop.key} className="flex items-center group min-h-[34px] -mx-2 rounded-md hover:bg-zinc-800/40 transition-colors">
                            <div className="flex items-center gap-1.5 text-xs text-zinc-500 w-28 px-2 shrink-0">
                                <Icon className="w-3.5 h-3.5" /><span>{prop.label}</span>
                            </div>
                            <input
                                type="text"
                                value={finding[prop.key]}
                                onChange={(e) => onUpdate(prop.key, e.target.value)}
                                placeholder="Empty"
                                className="flex-1 bg-transparent text-xs text-zinc-300 placeholder-zinc-600 outline-none px-2 py-1 rounded hover:bg-zinc-700/30 focus:bg-zinc-700/30 transition-colors"
                            />
                            <button onClick={() => removeProperty(prop.key)} className="p-1 text-zinc-600 hover:text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity mr-1" title="Remove">×</button>
                        </div>
                    );
                })}

                {/* Add Property button */}
                {hiddenProps.length > 0 && (
                    <div className="relative -mx-2" ref={addRef}>
                        <button
                            onClick={() => setAddOpen(!addOpen)}
                            className="flex items-center gap-1.5 text-xs text-zinc-600 hover:text-zinc-400 px-2 py-1.5 rounded transition-colors hover:bg-zinc-800/40"
                        >
                            <Plus className="w-3.5 h-3.5" />
                            Add property
                        </button>
                        {addOpen && (
                            <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-[180px]">
                                <div className="px-2.5 py-1.5 text-[10px] text-zinc-500 uppercase tracking-wider font-semibold">Add property</div>
                                {hiddenProps.map((prop) => {
                                    const Icon = prop.icon;
                                    return (
                                        <button
                                            key={prop.key}
                                            onClick={() => addProperty(prop.key)}
                                            className="w-full flex items-center gap-2.5 text-left px-2.5 py-2 transition-colors rounded-sm mx-0.5 hover:bg-zinc-800/60"
                                            style={{ width: 'calc(100% - 4px)' }}
                                        >
                                            <Icon className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
                                            <div>
                                                <div className="text-xs text-zinc-300">{prop.label}</div>
                                                <div className="text-[10px] text-zinc-600 leading-tight">{prop.desc}</div>
                                            </div>
                                        </button>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
