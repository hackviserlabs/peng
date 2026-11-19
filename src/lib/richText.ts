import createDOMPurify from 'dompurify';

const purifier = createDOMPurify(window);
purifier.addHook('uponSanitizeAttribute', (_node, attribute) => {
    if (attribute.attrName === 'class') {
        attribute.attrValue = attribute.attrValue.split(/\s+/)
            .filter(name => /^(?:language-|hljs-)[\w-]+$/.test(name) || name === 'hljs')
            .join(' ');
        attribute.keepAttr = Boolean(attribute.attrValue);
    }
});

export function sanitizeRichText(html: string) {
    return purifier.sanitize(html, {
        ALLOWED_TAGS: [
            'a', 'b', 'blockquote', 'br', 'caption', 'code', 'del', 'div', 'em', 'h1', 'h2',
            'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li', 'ol', 'p', 'pre', 's', 'span',
            'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'u', 'ul',
        ],
        ALLOWED_ATTR: ['alt', 'class', 'colspan', 'height', 'href', 'rowspan', 'src', 'start', 'title', 'width'],
        ALLOW_DATA_ATTR: false,
        ALLOW_ARIA_ATTR: false,
    });
}
