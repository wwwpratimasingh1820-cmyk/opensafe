/**
 * OpenSafe - SSL/TLS Analyzer
 * Analyzes SSL/TLS security and HTTPS configuration
 */

class SslAnalyzer {
    /**
     * Analyze SSL/TLS security
     * @param {string} url - Target URL
     * @param {object} headers - Response headers
     * @param {Document} doc - Parsed document
     * @returns {object} - Analysis results
     */
    async analyze(url, headers, doc) {
        const urlObj = new URL(url);
        const checks = [];
        const issues = [];
        const details = [];

        // Check 1: HTTPS Protocol
        const isHttps = urlObj.protocol === 'https:';
        checks.push({
            name: 'HTTPS Protocol',
            passed: isHttps,
            weight: 3,
        });

        if (!isHttps) {
            issues.push({
                severity: 'high',
                message: 'Website does not use HTTPS encryption',
                recommendation: 'Avoid entering sensitive information',
            });
        }

        details.push({
            label: 'Protocol',
            value: urlObj.protocol.replace(':', ''),
            status: isHttps ? 'safe' : 'danger',
        });

        // Check 2: Mixed Content Detection
        const mixedContent = this.detectMixedContent(doc, isHttps);
        checks.push({
            name: 'Mixed Content',
            passed: mixedContent.length === 0,
            weight: 2,
        });

        if (mixedContent.length > 0) {
            issues.push({
                severity: 'medium',
                message: `${mixedContent.length} insecure resources loaded over HTTP`,
                recommendation: 'Mixed content can compromise security',
            });
        }

        details.push({
            label: 'Mixed Content',
            value: mixedContent.length === 0 ? 'None detected' : `${mixedContent.length} resources`,
            status: mixedContent.length === 0 ? 'safe' : 'warning',
        });

        // Check 3: HSTS Header
        const hsts = headers['strict-transport-security'];
        const hasHsts = !!hsts;
        checks.push({
            name: 'HSTS',
            passed: hasHsts,
            weight: 2,
        });

        if (!hasHsts && isHttps) {
            issues.push({
                severity: 'low',
                message: 'HSTS header not present',
                recommendation: 'Website could enforce HTTPS more strictly',
            });
        }

        details.push({
            label: 'HSTS',
            value: hasHsts ? 'Enabled' : 'Not enabled',
            status: hasHsts ? 'safe' : 'warning',
        });

        // Check 4: Security Headers
        const securityHeaders = this.checkSecurityHeaders(headers);
        checks.push({
            name: 'Security Headers',
            passed: securityHeaders.score > 0.5,
            weight: 2,
        });

        details.push({
            label: 'Security Headers',
            value: `${securityHeaders.present}/${securityHeaders.total} present`,
            status: securityHeaders.score > 0.7 ? 'safe' : securityHeaders.score > 0.4 ? 'warning' : 'danger',
        });

        // Calculate module score
        const score = this.calculateScore(checks);
        const confidence = isHttps ? 85 : 95; // Higher confidence when analyzing HTTP

        return {
            score,
            confidence,
            checks,
            issues,
            details,
            summary: this.generateSummary(score, isHttps, issues),
            mixedContent,
            securityHeaders: securityHeaders.headers,
        };
    }

    /**
     * Detect mixed content (HTTP resources on HTTPS page)
     */
    detectMixedContent(doc, isHttps) {
        if (!isHttps) return [];

        const mixedContent = [];
        const selectors = [
            'script[src^="http:"]',
            'link[href^="http:"]',
            'img[src^="http:"]',
            'iframe[src^="http:"]',
            'video[src^="http:"]',
            'audio[src^="http:"]',
        ];

        selectors.forEach(selector => {
            doc.querySelectorAll(selector).forEach(el => {
                mixedContent.push({
                    type: el.tagName.toLowerCase(),
                    src: el.src || el.href,
                });
            });
        });

        return mixedContent;
    }

    /**
     * Check security headers
     */
    checkSecurityHeaders(headers) {
        const requiredHeaders = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
        };

        const headerResults = {};
        let present = 0;

        for (const [header, name] of Object.entries(requiredHeaders)) {
            const value = headers[header];
            headerResults[name] = {
                present: !!value,
                value: value || null,
            };
            if (value) present++;
        }

        return {
            headers: headerResults,
            present,
            total: Object.keys(requiredHeaders).length,
            score: present / Object.keys(requiredHeaders).length,
        };
    }

    /**
     * Calculate module score
     */
    calculateScore(checks) {
        let totalWeight = 0;
        let passedWeight = 0;

        for (const check of checks) {
            totalWeight += check.weight;
            if (check.passed) {
                passedWeight += check.weight;
            }
        }

        return Math.round((passedWeight / totalWeight) * 100);
    }

    /**
     * Generate summary
     */
    generateSummary(score, isHttps, issues) {
        if (!isHttps) {
            return 'Insecure HTTP connection';
        }
        if (score >= 90) {
            return 'Strong SSL/TLS configuration';
        }
        if (issues.length > 0) {
            return issues[0].message;
        }
        return 'Standard encryption active';
    }
}

export default new SslAnalyzer();
