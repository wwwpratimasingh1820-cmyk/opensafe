/**
 * OpenSafe - URL Analyzer Utility
 * Analyzes URL structure for suspicious patterns
 */

class UrlAnalyzer {
    /**
     * Analyze URL structure
     * @param {string} url - URL to analyze
     * @returns {object} - Analysis results
     */
    analyze(url) {
        try {
            const urlObj = new URL(url);

            return {
                protocol: urlObj.protocol,
                hostname: urlObj.hostname,
                domain: this.extractDomain(urlObj.hostname),
                subdomains: this.extractSubdomains(urlObj.hostname),
                path: urlObj.pathname,
                params: this.extractParams(urlObj.search),
                length: url.length,
                hasIpAddress: this.hasIpAddress(urlObj.hostname),
                hasPort: urlObj.port !== '',
                port: urlObj.port,
                suspiciousPatterns: this.detectSuspiciousPatterns(url, urlObj),
            };
        } catch (error) {
            return null;
        }
    }

    /**
     * Extract root domain
     */
    extractDomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    }

    /**
     * Extract subdomains
     */
    extractSubdomains(hostname) {
        const parts = hostname.split('.');
        if (parts.length > 2) {
            return parts.slice(0, -2);
        }
        return [];
    }

    /**
     * Extract URL parameters
     */
    extractParams(search) {
        const params = {};
        const urlParams = new URLSearchParams(search);
        for (const [key, value] of urlParams) {
            params[key] = value;
        }
        return params;
    }

    /**
     * Check if hostname is an IP address
     */
    hasIpAddress(hostname) {
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname);
    }

    /**
     * Detect suspicious URL patterns
     */
    detectSuspiciousPatterns(url, urlObj) {
        const patterns = [];

        // Excessive length
        if (url.length > 200) {
            patterns.push({
                type: 'excessive_length',
                description: 'URL is unusually long',
                severity: 'medium',
            });
        }

        // Too many subdomains
        const subdomains = this.extractSubdomains(urlObj.hostname);
        if (subdomains.length > 3) {
            patterns.push({
                type: 'excessive_subdomains',
                description: `${subdomains.length} subdomains detected`,
                severity: 'medium',
            });
        }

        // IP address instead of domain
        if (this.hasIpAddress(urlObj.hostname)) {
            patterns.push({
                type: 'ip_address',
                description: 'Using IP address instead of domain name',
                severity: 'high',
            });
        }

        // Hex encoding in path
        if (/%[0-9a-fA-F]{2}/.test(urlObj.pathname)) {
            const hexCount = (urlObj.pathname.match(/%[0-9a-fA-F]{2}/g) || []).length;
            if (hexCount > 3) {
                patterns.push({
                    type: 'excessive_encoding',
                    description: 'Excessive URL encoding detected',
                    severity: 'medium',
                });
            }
        }

        // @ symbol in URL (often used in phishing)
        if (url.includes('@')) {
            patterns.push({
                type: 'at_symbol',
                description: '@ symbol in URL (phishing technique)',
                severity: 'high',
            });
        }

        // Double slashes in path
        if (urlObj.pathname.includes('//')) {
            patterns.push({
                type: 'double_slashes',
                description: 'Double slashes in path',
                severity: 'low',
            });
        }

        // Suspicious TLD
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
        const hostname = urlObj.hostname.toLowerCase();
        for (const tld of suspiciousTlds) {
            if (hostname.endsWith(tld)) {
                patterns.push({
                    type: 'suspicious_tld',
                    description: `Suspicious TLD: ${tld}`,
                    severity: 'medium',
                });
                break;
            }
        }

        // Non-standard port
        if (urlObj.port && !['80', '443', '8080'].includes(urlObj.port)) {
            patterns.push({
                type: 'non_standard_port',
                description: `Non-standard port: ${urlObj.port}`,
                severity: 'low',
            });
        }

        return patterns;
    }

    /**
     * Calculate Levenshtein distance between two strings
     * Used for brand similarity detection
     */
    levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    /**
     * Check similarity to known brands
     */
    checkBrandSimilarity(domain) {
        const knownBrands = [
            'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
            'twitter', 'instagram', 'netflix', 'spotify', 'linkedin', 'github',
            'dropbox', 'adobe', 'oracle', 'salesforce', 'ebay', 'walmart'
        ];

        const domainLower = domain.toLowerCase().replace(/[^a-z]/g, '');
        const similarities = [];

        for (const brand of knownBrands) {
            const distance = this.levenshteinDistance(domainLower, brand);
            const similarity = 1 - (distance / Math.max(domainLower.length, brand.length));

            // If very similar but not exact match, it's suspicious
            if (similarity > 0.7 && similarity < 1.0) {
                similarities.push({
                    brand,
                    similarity: Math.round(similarity * 100),
                    suspicious: true,
                });
            }
        }

        return similarities;
    }
}

export default new UrlAnalyzer();
