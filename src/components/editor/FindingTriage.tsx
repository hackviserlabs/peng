import { FINDING_METADATA_LIMIT, FINDING_METADATA_LIST_LIMIT, TRIAGE_NOTES_LIMIT } from '../../constants';
import { FINDING_CONFIDENCES, FINDING_TARGET_FIELDS, type Finding, type UpdateFindingField } from '../../types';

const INPUT_STYLE = 'block w-full rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-sm text-zinc-200';
const BUTTON_STYLE = 'rounded-md px-2 py-1 text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 disabled:opacity-50';

const TARGET_LABELS = {
    url: 'URL',
    method: 'Method',
    parameter: 'Parameter',
    host: 'Host',
    port: 'Port',
};

export default function FindingTriage({ finding, onUpdate }: { finding: Finding; onUpdate: UpdateFindingField }) {
    const targets = finding.targets ?? [];

    return (
        <details className="mb-8 rounded-lg border border-zinc-800 bg-zinc-900/40 px-4 py-3">
            <summary className="cursor-pointer text-sm font-semibold text-zinc-200">Triage metadata</summary>
            <div className="mt-4 space-y-5 text-xs text-zinc-400">
                <div className="grid gap-3 sm:grid-cols-3">
                    <label className="space-y-1">
                        <span>Confidence</span>
                        <select
                            className={INPUT_STYLE}
                            value={finding.confidence ?? ''}
                            onChange={event => onUpdate('confidence', FINDING_CONFIDENCES.find(value => value === event.target.value))}
                        >
                            <option value="">Unspecified</option>
                            {FINDING_CONFIDENCES.map(value => (
                                <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>
                            ))}
                        </select>
                    </label>
                    {(['category', 'templateId'] as const).map(field => (
                        <label key={field} className="space-y-1">
                            <span>{field === 'category' ? 'Category' : 'Template ID'}</span>
                            <input
                                className={INPUT_STYLE}
                                maxLength={FINDING_METADATA_LIMIT}
                                value={finding[field] ?? ''}
                                onChange={event => onUpdate(field, event.target.value)}
                            />
                        </label>
                    ))}
                </div>

                <StringListField label="Tags" itemLabel="tag" values={finding.tags ?? []}
                    onChange={values => onUpdate('tags', values)} />
                <StringListField label="Evidence references" itemLabel="evidence reference" values={finding.evidence ?? []}
                    onChange={values => onUpdate('evidence', values)} />

                <fieldset className="space-y-2">
                    <legend className="font-semibold text-zinc-300">Targets</legend>
                    {targets.map((target, index) => (
                        <fieldset key={index} className="space-y-2 rounded-md border border-zinc-800 p-3">
                            <legend className="px-1">Target {index + 1}</legend>
                            <div className="grid gap-2 sm:grid-cols-2">
                                {FINDING_TARGET_FIELDS.map(field => (
                                    <label key={field} className={field === 'url' ? 'space-y-1 sm:col-span-2' : 'space-y-1'}>
                                        <span>{TARGET_LABELS[field]}</span>
                                        <input
                                            className={INPUT_STYLE}
                                            maxLength={FINDING_METADATA_LIMIT}
                                            value={target[field] ?? ''}
                                            onChange={event => {
                                                const value = event.target.value;
                                                onUpdate('targets', targets.map((item, i) => i === index ? { ...item, [field]: value } : item));
                                            }}
                                        />
                                    </label>
                                ))}
                            </div>
                            <button type="button" className={BUTTON_STYLE} aria-label={`Remove target ${index + 1}`}
                                onClick={() => onUpdate('targets', targets.filter((_, i) => i !== index))}>
                                Remove
                            </button>
                        </fieldset>
                    ))}
                    <button type="button" className={BUTTON_STYLE} disabled={targets.length >= FINDING_METADATA_LIST_LIMIT}
                        onClick={() => onUpdate('targets', [...targets, { url: '' }])}>
                        Add target
                    </button>
                </fieldset>

                <label className="block space-y-1">
                    <span className="font-semibold text-zinc-300">Triage notes (internal)</span>
                    <textarea
                        className={INPUT_STYLE}
                        rows={3}
                        maxLength={TRIAGE_NOTES_LIMIT}
                        value={finding.triageNotes ?? ''}
                        onChange={event => onUpdate('triageNotes', event.target.value)}
                    />
                </label>
            </div>
        </details>
    );
}

function StringListField({ label, itemLabel, values, onChange }: {
    label: string;
    itemLabel: string;
    values: string[];
    onChange: (values: string[]) => void;
}) {
    return (
        <fieldset className="space-y-2">
            <legend className="font-semibold text-zinc-300">{label}</legend>
            {values.map((value, index) => (
                <div key={index} className="flex items-start gap-2">
                    <textarea
                        aria-label={`${label} ${index + 1}`}
                        className={INPUT_STYLE}
                        rows={1}
                        maxLength={FINDING_METADATA_LIMIT}
                        value={value}
                        onChange={event => {
                            const text = event.target.value;
                            onChange(values.map((item, i) => i === index ? text : item));
                        }}
                    />
                    <button type="button" className={BUTTON_STYLE} aria-label={`Remove ${itemLabel} ${index + 1}`}
                        onClick={() => onChange(values.filter((_, i) => i !== index))}>
                        Remove
                    </button>
                </div>
            ))}
            <button type="button" className={BUTTON_STYLE} disabled={values.length >= FINDING_METADATA_LIST_LIMIT}
                onClick={() => onChange([...values, ''])}>
                Add {itemLabel}
            </button>
        </fieldset>
    );
}
