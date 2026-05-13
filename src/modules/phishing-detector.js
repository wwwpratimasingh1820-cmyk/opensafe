/**
 * OpenSafe - Phishing & Malware Detector
 * Detects phishing indicators and malicious patterns
 */

import urlAnalyzer from '../utils/url-analyzer.js';

class PhishingDetector {
    /**
     * Analyze for phishing and malware indicators
     * @param {string} url - Target URL
     * @param {Document} doc - Parsed document
     * @returns {object} - Analysis results
     */
    async analyze(url, doc) {
        const checks = [];
        const issues = [];
        const details = [];

        // Check 1: URL Structure Analysis
        const urlAnalysis = urlAnalyzer.analyze(url);
        const suspiciousPatterns = urlAnalysis.suspiciousPatterns;

        checks.push({
            name: 'URL Structure',
            passed: suspiciousPatterns.length === 0,
            weight: 3,
        });

        if (suspiciousPatterns.length > 0) {
            const highSeverity = suspiciousPatterns.filter(p => p.severity === 'high').length;
            issues.push({
                severity: highSeverity > 0 ? 'high' : 'medium',
                message: `${suspiciousPatterns.length} suspicious URL pattern(s) detected`,
                recommendation: 'URL structure indicates potential phishing',
            });
        }

        details.push({
            label: 'URL Patterns',
            value: suspiciousPatterns.length === 0 ? 'Clean' : `${suspiciousPatterns.length} suspicious`,
            status: suspiciousPatterns.length === 0 ? 'safe' : 'warning',
        });

        // Check 2: Brand Similarity (Typosquatting)
        const brandSimilarity = urlAnalyzer.checkBrandSimilarity(urlAnalysis.domain);
        checks.push({
            name: 'Brand Impersonation',
            passed: brandSimilarity.length === 0,
            weight: 3,
        });

        if (brandSimilarity.length > 0) {
            issues.push({
                severity: 'high',
                message: `Domain similar to "${brandSimilarity[0].brand}" (${brandSimilarity[0].similarity}% match)`,
                recommendation: 'Possible typosquatting/phishing attempt',
            });
        }

        details.push({
            label: 'Brand Similarity',
            value: brandSimilarity.length === 0 ? 'None' : `Similar to ${brandSimilarity[0].brand}`,
            status: brandSimilarity.length === 0 ? 'safe' : 'danger',
        });

        // Check 3: Fake Login Forms
        const loginForms = this.detectFakeLoginForms(doc, urlAnalysis.domain);
        checks.push({
            name: 'Login Form Security',
            passed: !loginForms.suspicious,
            weight: 2,
        });

        if (loginForms.suspicious) {
            issues.push({
                severity: 'high',
                message: loginForms.reason,
                recommendation: 'Do not enter credentials on this site',
            });
        }

        details.push({
            label: 'Login Forms',
            value: loginForms.count === 0 ? 'None' : `${loginForms.count} form(s)`,
            status: loginForms.suspicious ? 'danger' : 'safe',
        });

        // Check 4: Redirect Chains
        const redirects = this.detectRedirects(doc);
        checks.push({
            name: 'Redirect Behavior',
            passed: !redirects.suspicious,
            weight: 2,
        });

        if (redirects.suspicious) {
            issues.push({
                severity: 'medium',
                message: 'Suspicious redirect patterns detected',
                recommendation: 'Website may redirect to malicious sites',
            });
        }

        details.push({
            label: 'Redirects',
            value: redirects.count === 0 ? 'None' : `${redirects.count} detected`,
            status: redirects.suspicious ? 'warning' : 'safe',
        });

        // Check 5: Obfuscated Code
        const obfuscation = this.detectObfuscation(doc);
        checks.push({
            name: 'Code Obfuscation',
            passed: !obfuscation.detected,
            weight: 2,
        });

        if (obfuscation.detected) {
            issues.push({
                severity: 'medium',
                message: 'Obfuscated JavaScript detected',
                recommendation: 'Code obfuscation may hide malicious behavior',
            });
        }

        details.push({
            label: 'Obfuscation',
            value: obfuscation.detected ? `${obfuscation.count} instance(s)` : 'None',
            status: obfuscation.detected ? 'warning' : 'safe',
        });

        // Calculate module score
        const score = this.calculateScore(checks);
        const confidence = 80; // Good confidence for heuristic detection

        return {
            score,
            confidence,
            checks,
            issues,
            details,
            summary: this.generateSummary(score, issues.length),
            urlAnalysis,
            brandSimilarity,
            loginForms,
            redirects,
            obfuscation,
        };
    }

    /**
     * Detect fake login forms
     */
    detectFakeLoginForms(doc, domain) {
        const forms = doc.querySelectorAll('form');
        let loginFormCount = 0;
        let suspicious = false;
        let reason = '';

        forms.forEach(form => {
            const hasPassword = form.querySelector('input[type="password"]');
            const hasEmail = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');

            if (hasPassword && hasEmail) {
                loginFormCount++;

                // Check if form action goes to different domain
                if (form.action) {
                    try {
                        const actionUrl = new URL(form.action);
                        const actionDomain = this.extractDomain(actionUrl.hostname);

                        if (actionDomain !== domain && !this.isKnownAuthProvider(actionDomain)) {
                            suspicious = true;
                            reason = 'Login form submits to different domain';
                        }
                    } catch (e) {
                        // Invalid action URL
                    }
                }

                // Check for suspicious form attributes
                if (form.method.toLowerCase() === 'get' && hasPassword) {
                    suspicious = true;
                    reason = 'Password form uses insecure GET method';
                }
            }
        });

        return {
            count: loginFormCount,
            suspicious,
            reason,
        };
    }

    /**
     * Check if domain is a known auth provider
     */
    isKnownAuthProvider(domain) {
        const providers = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'github.com'];
        return providers.some(provider => domain.includes(provider));
    }

    /**
     * Detect suspicious redirects
     */
    detectRedirects(doc) {
        let count = 0;
        let suspicious = false;

        // Check meta refresh
        const metaRefresh = doc.querySelector('meta[http-equiv="refresh"]');
        if (metaRefresh) {
            count++;
            const content = metaRefresh.getAttribute('content');
            // Immediate redirects (< 2 seconds) are suspicious
            if (content && parseInt(content) < 2) {
                suspicious = true;
            }
        }

        // Check for JavaScript redirects
        const scripts = doc.querySelectorAll('script');
        scripts.forEach(script => {
            const content = script.textContent;
            if (content.includes('window.location') || content.includes('document.location')) {
                count++;
                // Multiple redirects are suspicious
                if (count > 2) {
                    suspicious = true;
                }
            }
        });

        return {
            count,
            suspicious,
        };
    }

    /**
     * Detect code obfuscation
     */
    detectObfuscation(doc) {
        let count = 0;
        const scripts = doc.querySelectorAll('script');

        scripts.forEach(script => {
            const content = script.textContent;

            // Check for common obfuscation patterns
            const patterns = [
                /eval\s*\(\s*atob/gi,  // Base64 decode + eval
                /\\x[0-9a-f]{2}/gi,     // Hex encoding
                /\\u[0-9a-f]{4}/gi,     // Unicode encoding
                /_0x[0-9a-f]+/gi,       // Hex variable names
            ];

            patterns.forEach(pattern => {
                const matches = content.match(pattern);
                if (matches && matches.length > 5) {
                    count++;
                }
            });
        });

        return {
            detected: count > 0,
            count,
        };
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
    generateSummary(score, issueCount) {
        if (score >= 80) {
            return 'No phishing indicators detected';
        }
        if (score >= 60) {
            return `${issueCount} minor phishing indicator(s)`;
        }
        return `${issueCount} phishing indicator(s) detected - HIGH RISK`;
    }
}

export default new PhishingDetector();
