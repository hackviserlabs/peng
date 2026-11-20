import { ALL_TEMPLATES } from '../src/data/templates/index.ts';

export const templates = ALL_TEMPLATES;
export const templatesById = new Map(templates.map((template) => [template.id, template]));

const entities = { amp: '&', apos: "'", gt: '>', lt: '<', nbsp: ' ', quot: '"' };
function decodeEntities(value) {
  return value.replace(/&(amp|apos|gt|lt|nbsp|quot|#\d+|#x[\da-f]+);/gi, (entity, name) => {
    if (!name.startsWith('#')) return entities[name.toLowerCase()];
    const codePoint = name[1].toLowerCase() === 'x' ? parseInt(name.slice(2), 16) : Number(name.slice(1));
    return codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : entity;
  });
}

function plainRemediation(html) {
  return decodeEntities(html
    .replace(/<li\b[^>]*>/gi, '• ')
    .replace(/<\/(?:p|li|ol|ul|h[1-6])>|<br\s*\/?>/gi, '\n')
    .replace(/<[^>]*>/g, ''))
    .split('\n').map((line) => line.trim()).filter(Boolean).join('\n');
}

function referenceUrls(html) {
  const links = [...html.matchAll(/<a\b[^>]*\bhref\s*=\s*["'](https?:\/\/[^"']+)["']/gi)];
  return [...new Set(links.map(([, href]) => decodeEntities(href)))];
}

export function templateDetails(template) {
  const { id, title, severity, category, cwe, tags, remediation, references = '' } = template;
  return {
    id, category, tags,
    defaults: { title, severity, ...(cwe ? { cwe } : {}) },
    remediation_hint: plainRemediation(remediation),
    references: referenceUrls(references),
  };
}

export function templateFindingFields(template) {
  const { category, tags, defaults, remediation_hint, references } = templateDetails(template);
  return { ...defaults, category, tags, remediation: remediation_hint, references: references.join('\n') };
}

export function catalogSummaries(query, category) {
  const terms = query?.toLowerCase().split(/\s+/) ?? [];
  return templates.filter((template) => {
    if (category && template.category.toLowerCase() !== category.toLowerCase()) return false;
    const searchable = [template.id, template.title, template.category, template.severity, template.cwe, ...template.tags]
      .join(' ').toLowerCase();
    return terms.every((term) => searchable.includes(term));
  }).map(({ id, title, category, severity }) => ({ id, title, category, severity }));
}
