/**
 * OpenSafe - Security Sanitzation Utility
 * Provides functions to safely handle untrusted content and prevent XSS
 */

/**
 * Escapes HTML special characters to prevent XSS
 * @param {any} str - The string to escape
 * @returns {string} - Escaped string
 */
export function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    const stringValue = String(str);
    return stringValue
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Sanitizes a URL for safe display/usage
 * @param {string} url - The URL to sanitize
 * @returns {string} - Sanitized URL
 */
export function sanitizeURL(url) {
    if (!url) return '';
    try {
        const parsed = new URL(url);
        // Only allow http and https
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return 'about:blank';
        }
        return parsed.href;
    } catch {
        return 'about:blank';
    }
}
