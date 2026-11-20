import { useMemo, useState, useRef, useEffect } from 'react';
import type { Severity } from '../../types';
import {
    type CvssBaseMetrics,
    DEFAULT_CVSS_METRICS,
    calculateCvssScore,
    buildCvssVector,
    mapCvssScoreToSeverity,
    parseCvssVector,
} from '../../lib/cvss';

interface CvssCalculatorModalProps {
    onClose: () => void;
    savedScore: string;
    initialVector?: string;
    onApply: (result: { score: string; severity: Severity; vector: string; applySeverity: boolean }) => void;
}

function useDropdown() {
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement | null>(null);
    useEffect(() => {
        function handleClick(e: MouseEvent) {
            if (ref.current && !ref.current.contains(e.target as Node)) {
                setOpen(false);
            }
        }
        if (open) document.addEventListener('mousedown', handleClick);
        return () => document.removeEventListener('mousedown', handleClick);
    }, [open]);
    return { open, setOpen, ref };
}

export default function CvssCalculatorModal({ onClose, savedScore, initialVector, onApply }: CvssCalculatorModalProps) {
    const [metrics, setMetrics] = useState<CvssBaseMetrics>(() =>
        parseCvssVector(initialVector ?? '') ?? DEFAULT_CVSS_METRICS);
    const [applySeverity, setApplySeverity] = useState(true);

    const { ref: avRef, open: avOpen, setOpen: setAVOpen } = useDropdown();
    const { ref: acRef, open: acOpen, setOpen: setACOpen } = useDropdown();
    const { ref: prRef, open: prOpen, setOpen: setPROpen } = useDropdown();
    const { ref: uiRef, open: uiOpen, setOpen: setUIOpen } = useDropdown();
    const { ref: sRef, open: sOpen, setOpen: setSOpen } = useDropdown();
    const { ref: cRef, open: cOpen, setOpen: setCOpen } = useDropdown();
    const { ref: iRef, open: iOpen, setOpen: setIOpen } = useDropdown();
    const { ref: aRef, open: aOpen, setOpen: setAOpen } = useDropdown();

    const { score, vector, severity } = useMemo(() => {
        const s = calculateCvssScore(metrics);
        const v = buildCvssVector(metrics);
        const sev = mapCvssScoreToSeverity(s);
        return {
            score: s,
            vector: v,
            severity: sev,
        };
    }, [metrics]);

    const savedScoreValue = savedScore.trim();
    const showMissingVectorNote = !initialVector?.trim()
        && savedScoreValue !== ''
        && Number.isFinite(Number(savedScoreValue))
        && Number(savedScoreValue) !== score;

    const handleApply = () => {
        onApply({
            score: score.toFixed(1),
            severity,
            vector,
            applySeverity,
        });
        onClose();
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
            <div className="bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl w-full max-w-xl mx-4">
                <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
                    <div>
                        <h2 className="text-sm font-semibold text-zinc-100">CVSS v3.x Calculator</h2>
                        <p className="text-[11px] text-zinc-500">Base score &amp; severity will be calculated from the selected metrics.</p>
                    </div>
                    <button
                        type="button"
                        onClick={onClose}
                        className="text-zinc-500 hover:text-zinc-300 text-sm px-2 py-1"
                    >
                        ✕
                    </button>
                </div>

                <div className="px-4 py-3 space-y-4 max-h-[70vh] overflow-y-auto">
                    <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Attack Vector (AV)</label>
                            <div className="relative" ref={avRef}>
                                <button
                                    type="button"
                                    onClick={() => setAVOpen(!avOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.AV === 'N' && 'Network (N)'}
                                        {metrics.AV === 'A' && 'Adjacent (A)'}
                                        {metrics.AV === 'L' && 'Local (L)'}
                                        {metrics.AV === 'P' && 'Physical (P)'}
                                    </span>
                                </button>
                                {avOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'N', label: 'Network (N)' },
                                            { value: 'A', label: 'Adjacent (A)' },
                                            { value: 'L', label: 'Local (L)' },
                                            { value: 'P', label: 'Physical (P)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, AV: opt.value as CvssBaseMetrics['AV'] }));
                                                    setAVOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.AV === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Attack Complexity (AC)</label>
                            <div className="relative" ref={acRef}>
                                <button
                                    type="button"
                                    onClick={() => setACOpen(!acOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.AC === 'L' && 'Low (L)'}
                                        {metrics.AC === 'H' && 'High (H)'}
                                    </span>
                                </button>
                                {acOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'L', label: 'Low (L)' },
                                            { value: 'H', label: 'High (H)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, AC: opt.value as CvssBaseMetrics['AC'] }));
                                                    setACOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.AC === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Privileges Required (PR)</label>
                            <div className="relative" ref={prRef}>
                                <button
                                    type="button"
                                    onClick={() => setPROpen(!prOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.PR === 'N' && 'None (N)'}
                                        {metrics.PR === 'L' && 'Low (L)'}
                                        {metrics.PR === 'H' && 'High (H)'}
                                    </span>
                                </button>
                                {prOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'N', label: 'None (N)' },
                                            { value: 'L', label: 'Low (L)' },
                                            { value: 'H', label: 'High (H)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, PR: opt.value as CvssBaseMetrics['PR'] }));
                                                    setPROpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.PR === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">User Interaction (UI)</label>
                            <div className="relative" ref={uiRef}>
                                <button
                                    type="button"
                                    onClick={() => setUIOpen(!uiOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.UI === 'N' && 'None (N)'}
                                        {metrics.UI === 'R' && 'Required (R)'}
                                    </span>
                                </button>
                                {uiOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'N', label: 'None (N)' },
                                            { value: 'R', label: 'Required (R)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, UI: opt.value as CvssBaseMetrics['UI'] }));
                                                    setUIOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.UI === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Scope (S)</label>
                            <div className="relative" ref={sRef}>
                                <button
                                    type="button"
                                    onClick={() => setSOpen(!sOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.S === 'U' && 'Unchanged (U)'}
                                        {metrics.S === 'C' && 'Changed (C)'}
                                    </span>
                                </button>
                                {sOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'U', label: 'Unchanged (U)' },
                                            { value: 'C', label: 'Changed (C)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, S: opt.value as CvssBaseMetrics['S'] }));
                                                    setSOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.S === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div />

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Confidentiality (C)</label>
                            <div className="relative" ref={cRef}>
                                <button
                                    type="button"
                                    onClick={() => setCOpen(!cOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.C === 'N' && 'None (N)'}
                                        {metrics.C === 'L' && 'Low (L)'}
                                        {metrics.C === 'H' && 'High (H)'}
                                    </span>
                                </button>
                                {cOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'N', label: 'None (N)' },
                                            { value: 'L', label: 'Low (L)' },
                                            { value: 'H', label: 'High (H)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, C: opt.value as CvssBaseMetrics['C'] }));
                                                    setCOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.C === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Integrity (I)</label>
                            <div className="relative" ref={iRef}>
                                <button
                                    type="button"
                                    onClick={() => setIOpen(!iOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.I === 'N' && 'None (N)'}
                                        {metrics.I === 'L' && 'Low (L)'}
                                        {metrics.I === 'H' && 'High (H)'}
                                    </span>
                                </button>
                                {iOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'N', label: 'None (N)' },
                                            { value: 'L', label: 'Low (L)' },
                                            { value: 'H', label: 'High (H)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, I: opt.value as CvssBaseMetrics['I'] }));
                                                    setIOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.I === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">Availability (A)</label>
                            <div className="relative" ref={aRef}>
                                <button
                                    type="button"
                                    onClick={() => setAOpen(!aOpen)}
                                    className="w-full flex items-center justify-between text-xs px-2 py-1.5 rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 hover:bg-zinc-800/60 hover:border-zinc-600 transition-colors"
                                >
                                    <span>
                                        {metrics.A === 'N' && 'None (N)'}
                                        {metrics.A === 'L' && 'Low (L)'}
                                        {metrics.A === 'H' && 'High (H)'}
                                    </span>
                                </button>
                                {aOpen && (
                                    <div className="absolute top-full left-0 mt-1 z-50 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl py-1 min-w-full">
                                        {[
                                            { value: 'N', label: 'None (N)' },
                                            { value: 'L', label: 'Low (L)' },
                                            { value: 'H', label: 'High (H)' },
                                        ].map((opt) => (
                                            <button
                                                key={opt.value}
                                                type="button"
                                                onClick={() => {
                                                    setMetrics((prev) => ({ ...prev, A: opt.value as CvssBaseMetrics['A'] }));
                                                    setAOpen(false);
                                                }}
                                                className={`w-full text-left text-xs px-2.5 py-1.5 transition-colors ${
                                                    metrics.A === opt.value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-300 hover:bg-zinc-800/60'
                                                }`}
                                            >
                                                {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="border border-zinc-800 rounded-lg p-3 bg-zinc-950/60">
                        {showMissingVectorNote && (
                            <p role="status" className="mb-3 rounded-md border border-amber-500/20 bg-amber-500/10 px-2.5 py-2 text-xs text-amber-300">
                                This finding saved a CVSS score of {savedScoreValue} without a vector. The calculator uses the metrics shown above, so its score differs.
                            </p>
                        )}
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-[11px] text-zinc-500 uppercase tracking-wide mb-1">Base Score</div>
                                <div className="flex items-baseline gap-2">
                                    <span className="text-2xl font-semibold text-zinc-50">{score.toFixed(1)}</span>
                                    <span className="text-xs text-zinc-500">/ 10.0</span>
                                </div>
                            </div>
                            <div className="text-right">
                                <div className="text-[11px] text-zinc-500 uppercase tracking-wide mb-1">Severity</div>
                                <span className="inline-flex items-center px-2 py-1 rounded-full text-[11px] font-medium bg-zinc-800/80 text-zinc-100">
                                    {severity}
                                </span>
                            </div>
                        </div>
                        <div className="mt-2">
                            <div className="text-[11px] text-zinc-500 uppercase tracking-wide mb-1">Vector</div>
                            <div className="text-[11px] font-mono text-zinc-300 break-all bg-zinc-900/80 border border-zinc-800 rounded px-2 py-1.5">
                                {vector}
                            </div>
                        </div>
                        <label className="mt-3 flex items-center gap-2 text-[11px] text-zinc-400">
                            <input
                                type="checkbox"
                                checked={applySeverity}
                                onChange={(e) => setApplySeverity(e.target.checked)}
                                className="w-3 h-3 rounded border-zinc-700 bg-zinc-950 text-zinc-50"
                            />
                            Also update Risk Level to match this CVSS severity
                        </label>
                    </div>
                </div>

                <div className="px-4 py-3 border-t border-zinc-800 flex items-center justify-end gap-2">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-3 py-1.5 text-xs rounded-md border border-zinc-700 text-zinc-300 hover:bg-zinc-800/60 hover:border-zinc-500 transition-colors"
                    >
                        Cancel
                    </button>
                    <button
                        type="button"
                        onClick={handleApply}
                        className="px-3 py-1.5 text-xs rounded-md bg-emerald-500 text-black font-medium hover:bg-emerald-400 transition-colors"
                    >
                        Apply to finding
                    </button>
                </div>
            </div>
        </div>
    );
}

