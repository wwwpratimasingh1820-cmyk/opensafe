/**
 * OpenSafe - DOM Parser Utility
 * Efficient HTML parsing and analysis
 */

class DomParser {
    /**
     * Parse HTML string into DOM
     * @param {string} html - HTML content
     * @returns {Document} - Parsed document
     */
    parse(html) {
        const parser = new DOMParser();
        return parser.parseFromString(html, 'text/html');
    }

    /**
     * Extract all scripts from document
     */
    extractScripts(doc) {
        const scripts = [];
        const scriptElements = doc.querySelectorAll('script');

        scriptElements.forEach(script => {
            scripts.push({
                src: script.src || null,
                inline: !script.src,
                content: script.textContent,
                async: script.async,
                defer: script.defer,
                type: script.type || 'text/javascript',
            });
        });

        return scripts;
    }

    /**
     * Extract all external resources
     */
    extractResources(doc) {
        const resources = {
            stylesheets: [],
            images: [],
            iframes: [],
            links: [],
        };

        // Stylesheets
        doc.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
            resources.stylesheets.push({
                href: link.href,
                media: link.media,
            });
        });

        // Images
        doc.querySelectorAll('img').forEach(img => {
            resources.images.push({
                src: img.src,
                alt: img.alt,
                width: img.width,
                height: img.height,
            });
        });

        // Iframes
        doc.querySelectorAll('iframe').forEach(iframe => {
            resources.iframes.push({
                src: iframe.src,
                sandbox: iframe.sandbox.value,
                allow: iframe.allow,
            });
        });

        // Links
        doc.querySelectorAll('a[href]').forEach(link => {
            resources.links.push({
                href: link.href,
                text: link.textContent.trim(),
                rel: link.rel,
                target: link.target,
            });
        });

        return resources;
    }

    /**
     * Extract meta tags
     */
    extractMetaTags(doc) {
        const meta = {};

        doc.querySelectorAll('meta').forEach(tag => {
            const name = tag.getAttribute('name') || tag.getAttribute('property');
            const content = tag.getAttribute('content');

            if (name && content) {
                meta[name] = content;
            }
        });

        return meta;
    }

    /**
     * Extract forms
     */
    extractForms(doc) {
        const forms = [];

        doc.querySelectorAll('form').forEach(form => {
            const inputs = [];
            form.querySelectorAll('input, textarea, select').forEach(input => {
                inputs.push({
                    type: input.type,
                    name: input.name,
                    id: input.id,
                    required: input.required,
                });
            });

            forms.push({
                action: form.action,
                method: form.method,
                inputs,
                hasPasswordField: inputs.some(i => i.type === 'password'),
            });
        });

        return forms;
    }

    /**
     * Extract text content (for keyword analysis)
     */
    extractTextContent(doc) {
        // Remove script and style elements
        const clone = doc.cloneNode(true);
        clone.querySelectorAll('script, style, noscript').forEach(el => el.remove());

        return clone.body ? clone.body.textContent.trim() : '';
    }

    /**
     * Count elements
     */
    countElements(doc) {
        return {
            total: doc.querySelectorAll('*').length,
            scripts: doc.querySelectorAll('script').length,
            iframes: doc.querySelectorAll('iframe').length,
            forms: doc.querySelectorAll('form').length,
            images: doc.querySelectorAll('img').length,
            links: doc.querySelectorAll('a').length,
        };
    }

    /**
     * Check for specific patterns
     */
    hasPattern(doc, selector) {
        return doc.querySelectorAll(selector).length > 0;
    }

    /**
     * Get document title
     */
    getTitle(doc) {
        return doc.title || '';
    }

    /**
     * Check if document has specific security headers in meta tags
     */
    hasSecurityMeta(doc) {
        const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
        const xframe = doc.querySelector('meta[http-equiv="X-Frame-Options"]');

        return {
            hasCSP: !!csp,
            cspContent: csp ? csp.getAttribute('content') : null,
            hasXFrame: !!xframe,
            xframeContent: xframe ? xframe.getAttribute('content') : null,
        };
    }
}

export default new DomParser();
