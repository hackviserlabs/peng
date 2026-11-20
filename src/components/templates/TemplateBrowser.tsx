import { sanitizeRichText } from '../../lib/richText';
import { useState, useCallback, useEffect } from 'react';
import { X, Search, Shield, Globe, Server, Wifi, Smartphone, Cloud, Code, Lock, AlertTriangle, Eye, Zap, Bug, MoreHorizontal, Layers, Plus, ChevronLeft } from 'lucide-react';
import { SEVERITY_COLORS } from '../../constants';
import type { FindingTemplate, TemplateCategory } from '../../constants';
import { searchTemplates, getCategoriesWithCounts } from '../../lib/templateLib';

const CATEGORY_ICONS: Partial<Record<TemplateCategory | 'All', typeof Shield>> = {
    'All': Layers,
    'Injection': Code,
    'XSS': Zap,
    'Broken Access Control': Lock,
    'Authentication': Lock,
    'Cryptographic Failures': Shield,
    'Security Misconfiguration': AlertTriangle,
    'Information Disclosure': Eye,
    'SSRF': Server,
    'Business Logic': Bug,
    'API Security': Globe,
    'Network & Infrastructure': Wifi,
    'SSL/TLS': Shield,
    'Mobile': Smartphone,
    'Cloud': Cloud,
    'Other': MoreHorizontal,
};

interface TemplateBrowserProps {
    onSelect: (template: FindingTemplate) => void;
    onClose: () => void;
}

export default function TemplateBrowser({ onSelect, onClose }: TemplateBrowserProps) {
    const [query, setQuery] = useState('');
    const [selectedCategory, setSelectedCategory] = useState<TemplateCategory | 'All'>('All');
    const [previewTemplate, setPreviewTemplate] = useState<FindingTemplate | null>(null);
    const categories = getCategoriesWithCounts();
    const results = searchTemplates(query, selectedCategory);

    const handleAdd = useCallback((template: FindingTemplate) => {
        onSelect(template);
        onClose();
    }, [onSelect, onClose]);

    // Escape to close preview or browser
    useEffect(() => {
        const handleKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                if (previewTemplate) {
                    setPreviewTemplate(null);
                } else {
                    onClose();
                }
            }
        };
        window.addEventListener('keydown', handleKey);
        return () => window.removeEventListener('keydown', handleKey);
    }, [previewTemplate, onClose]);

    return (
        <div className="fixed inset-0 z-[100] flex bg-zinc-950/95 backdrop-blur-sm">
            <div className="flex flex-col w-full max-w-6xl mx-auto my-6 bg-zinc-900 rounded-2xl border border-zinc-800 shadow-2xl overflow-hidden">
                {/* Header */}
                <div className="flex items-center gap-4 px-6 py-4 border-b border-zinc-800 shrink-0">
                    {previewTemplate && (
                        <button
                            onClick={() => setPreviewTemplate(null)}
                            className="p-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg transition-colors"
                        >
                            <ChevronLeft className="w-5 h-5" />
                        </button>
                    )}
                    <div className="flex-1 relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                        <input
                            type="text"
                            value={query}
                            onChange={(e) => { setQuery(e.target.value); setPreviewTemplate(null); }}
                            placeholder="Search templates... (e.g. sql injection, CWE-79, SSRF)"
                            className="w-full bg-zinc-800 text-sm text-zinc-200 placeholder-zinc-500 pl-10 pr-4 py-2.5 rounded-lg border border-zinc-700 outline-none focus:border-emerald-500/50 transition-colors"
                            autoFocus
                        />
                    </div>
                    <span className="text-xs text-zinc-500 tabular-nums shrink-0">
                        {results.length} of {categories[0].count} templates
                    </span>
                    <button onClick={onClose} className="p-2 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg transition-colors" title="Close (Esc)">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Body */}
                <div className="flex flex-1 min-h-0">
                    {/* Category Sidebar */}
                    <div className="w-56 shrink-0 border-r border-zinc-800 overflow-y-auto py-2">
                        {categories.map((cat) => {
                            const Icon = CATEGORY_ICONS[cat.name] || MoreHorizontal;
                            const isActive = selectedCategory === cat.name;
                            return (
                                <button
                                    key={cat.name}
                                    onClick={() => { setSelectedCategory(cat.name); setPreviewTemplate(null); }}
                                    className={`w-full flex items-center gap-2.5 text-left text-sm px-4 py-2 transition-colors ${isActive
                                        ? 'bg-emerald-500/10 text-emerald-400 border-r-2 border-emerald-400'
                                        : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200'
                                        }`}
                                >
                                    <Icon className="w-4 h-4 shrink-0" />
                                    <span className="flex-1 truncate">{cat.name}</span>
                                    <span className={`text-[11px] tabular-nums ${isActive ? 'text-emerald-400/70' : 'text-zinc-600'}`}>
                                        {cat.count}
                                    </span>
                                </button>
                            );
                        })}
                    </div>

                    {/* Main Content: Grid or Preview */}
                    {previewTemplate ? (
                        <TemplatePreview template={previewTemplate} onAdd={handleAdd} />
                    ) : (
                        <div className="flex-1 overflow-y-auto p-4">
                            {results.length === 0 ? (
                                <div className="flex flex-col items-center justify-center h-full text-zinc-500">
                                    <Search className="w-8 h-8 mb-3 opacity-30" />
                                    <p className="text-sm">No templates found</p>
                                    <p className="text-xs mt-1">Try a different search term or category</p>
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                                    {results.map((template) => (
                                        <TemplateCard
                                            key={template.id}
                                            template={template}
                                            onAdd={handleAdd}
                                            onPreview={setPreviewTemplate}
                                        />
                                    ))}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

/* ====== Template Card ====== */
function TemplateCard({ template, onAdd, onPreview }: {
    template: FindingTemplate;
    onAdd: (t: FindingTemplate) => void;
    onPreview: (t: FindingTemplate) => void;
}) {
    const colors = SEVERITY_COLORS[template.severity];
    const descPreview = template.description.replace(/<[^>]+>/g, '').slice(0, 150) + '...';

    return (
        <div
            className="group flex flex-col bg-zinc-800/40 border border-zinc-800 hover:border-zinc-700 rounded-xl p-4 transition-all hover:bg-zinc-800/60 cursor-pointer"
            onClick={() => onPreview(template)}
        >
            <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-semibold text-zinc-100 leading-tight">{template.title}</h3>
                    <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${colors.bg} ${colors.text}`}>
                            {template.severity}
                        </span>
                        {template.cwe && (
                            <span className="text-[10px] text-zinc-500 font-mono">{template.cwe}</span>
                        )}
                        {template.cvss && (
                            <span className="text-[10px] text-zinc-500">CVSS {template.cvss}</span>
                        )}
                        {template.owasp && (
                            <span className="text-[10px] text-zinc-500 truncate max-w-[180px]">{template.owasp}</span>
                        )}
                    </div>
                </div>
                <button
                    onClick={(e) => { e.stopPropagation(); onAdd(template); }}
                    className="shrink-0 px-3 py-1.5 text-xs font-medium text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 rounded-lg border border-emerald-500/20 transition-colors opacity-0 group-hover:opacity-100"
                >
                    + Add
                </button>
            </div>
            <p className="text-xs text-zinc-500 leading-relaxed line-clamp-2">{descPreview}</p>
            <div className="flex items-center gap-1.5 mt-2.5">
                {template.tags.slice(0, 4).map((tag) => (
                    <span key={tag} className="text-[10px] text-zinc-600 bg-zinc-800 px-1.5 py-0.5 rounded">
                        {tag}
                    </span>
                ))}
            </div>
        </div>
    );
}

/* ====== Template Preview ====== */
function TemplatePreview({ template, onAdd }: { template: FindingTemplate; onAdd: (t: FindingTemplate) => void }) {
    const colors = SEVERITY_COLORS[template.severity];

    return (
        <div className="flex-1 overflow-y-auto p-6">
            {/* Preview Header */}
            <div className="flex items-start justify-between gap-4 mb-6">
                <div>
                    <h2 className="text-xl font-bold text-white mb-2">{template.title}</h2>
                    <div className="flex items-center gap-3 flex-wrap">
                        <span className={`text-xs font-bold px-2 py-1 rounded ${colors.bg} ${colors.text}`}>
                            {template.severity}
                        </span>
                        {template.cwe && <span className="text-xs text-zinc-400 font-mono">{template.cwe}</span>}
                        {template.cvss && <span className="text-xs text-zinc-400">CVSS {template.cvss}</span>}
                        {template.owasp && <span className="text-xs text-zinc-400">{template.owasp}</span>}
                    </div>
                    <div className="flex items-center gap-1.5 mt-3">
                        {template.tags.map((tag) => (
                            <span key={tag} className="text-[10px] text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">
                                {tag}
                            </span>
                        ))}
                    </div>
                </div>
                <button
                    onClick={() => onAdd(template)}
                    className="shrink-0 flex items-center gap-2 px-4 py-2 text-sm font-medium text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 rounded-lg border border-emerald-500/20 transition-colors"
                >
                    <Plus className="w-4 h-4" />
                    Add to Project
                </button>
            </div>

            {/* Preview Content Sections */}
            <div className="space-y-6">
                <PreviewSection title="Description" html={template.description} />
                <PreviewSection title="Impact" html={template.impact} />
                <PreviewSection title="Remediation" html={template.remediation} />
                {template.references && <PreviewSection title="References" html={template.references} />}
            </div>
        </div>
    );
}

function PreviewSection({ title, html }: { title: string; html: string }) {
    return (
        <div>
            <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-wider mb-2">{title}</h3>
            <div
                className="prose prose-sm prose-invert max-w-none text-zinc-300 leading-relaxed template-preview-prose"
                dangerouslySetInnerHTML={{ __html: sanitizeRichText(html) }}
            />
        </div>
    );
}
