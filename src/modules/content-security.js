/**
 * OpenSafe - Content Security Analyzer
 * Detects XSS vulnerabilities, clickjacking, and form security issues
 */

class ContentSecurityAnalyzer {
    /**
     * Analyze content security
     * @param {Document} doc - Parsed document
     * @param {object} headers - Response headers
     * @param {string} targetUrl - Target website URL
     * @returns {object} - Analysis results
     */
    async analyze(doc, headers, targetUrl) {
        const checks = [];
        const issues = [];
        const details = [];

        // Check 1: DOM-based XSS Patterns
        const xssPatterns = this.detectXssPatterns(doc, targetUrl);
        checks.push({
            name: 'XSS Vulnerabilities',
            passed: xssPatterns.length === 0,
            weight: 3,
        });

        if (xssPatterns.length > 0) {
            issues.push({
                severity: 'high',
                message: `${xssPatterns.length} potential XSS vulnerability pattern(s) detected`,
                recommendation: 'Website may be vulnerable to cross-site scripting attacks',
            });
        }

        details.push({
            label: 'XSS Patterns',
            value: xssPatterns.length === 0 ? 'None detected' : `${xssPatterns.length} found`,
            status: xssPatterns.length === 0 ? 'safe' : 'danger',
        });

        // Check 2: Clickjacking Protection
        const clickjackingProtection = this.checkClickjackingProtection(headers, doc);
        checks.push({
            name: 'Clickjacking Protection',
            passed: clickjackingProtection.protected,
            weight: 2,
        });

        if (!clickjackingProtection.protected) {
            issues.push({
                severity: 'medium',
                message: 'No clickjacking protection detected',
                recommendation: 'Website could be embedded in malicious iframes',
            });
        }

        details.push({
            label: 'Clickjacking Protection',
            value: clickjackingProtection.protected ? clickjackingProtection.method : 'Not protected',
            status: clickjackingProtection.protected ? 'safe' : 'warning',
        });

        // Check 3: Form Security
        const formSecurity = this.analyzeFormSecurity(doc);
        checks.push({
            name: 'Form Security',
            passed: formSecurity.secure,
            weight: 2,
        });

        if (!formSecurity.secure) {
            issues.push({
                severity: formSecurity.hasPasswordField ? 'high' : 'medium',
                message: formSecurity.message,
                recommendation: 'Forms may submit data insecurely',
            });
        }

        details.push({
            label: 'Form Security',
            value: formSecurity.summary,
            status: formSecurity.secure ? 'safe' : 'warning',
        });

        // Check 4: Iframe Injection
        const iframes = this.analyzeIframes(doc);
        checks.push({
            name: 'Iframe Security',
            passed: iframes.safe,
            weight: 1,
        });

        if (!iframes.safe) {
            issues.push({
                severity: 'medium',
                message: `${iframes.suspicious} suspicious iframe(s) detected`,
                recommendation: 'Iframes may load untrusted content',
            });
        }

        details.push({
            label: 'Iframes',
            value: `${iframes.total} total, ${iframes.suspicious} suspicious`,
            status: iframes.safe ? 'safe' : 'warning',
        });

        // Calculate module score
        const score = this.calculateScore(checks);
        const confidence = 75; // Medium confidence for client-side analysis

        return {
            score,
            confidence,
            checks,
            issues,
            details,
            summary: this.generateSummary(score, issues),
            xssPatterns,
            clickjackingProtection,
            formSecurity,
            iframes,
        };
    }

    /**
     * Detect XSS vulnerability patterns
     */
    detectXssPatterns(doc, targetUrl) {
        const patterns = [];
        const scripts = doc.querySelectorAll('script');

        scripts.forEach((script, index) => {
            const content = script.textContent;

            // Check for dangerous functions
            const dangerousFunctions = [
                { pattern: /eval\s*\(/gi, name: 'eval()' },
                { pattern: /document\.write\s*\(/gi, name: 'document.write()' },
                { pattern: /innerHTML\s*=/gi, name: 'innerHTML' },
                { pattern: /outerHTML\s*=/gi, name: 'outerHTML' },
                { pattern: /document\.location/gi, name: 'document.location' },
                { pattern: /window\.location/gi, name: 'window.location' },
            ];

            dangerousFunctions.forEach(({ pattern, name }) => {
                if (pattern.test(content)) {
                    patterns.push({
                        type: 'dangerous_function',
                        function: name,
                        scriptIndex: index,
                        inline: !script.src,
                    });
                }
            });

            // Check for untrusted script sources
            if (script.src && !this.isTrustedDomain(script.src, targetUrl)) {
                patterns.push({
                    type: 'untrusted_script',
                    src: script.src,
                    scriptIndex: index,
                });
            }
        });

        return patterns;
    }

    /**
     * Check if domain is trusted
     */
    isTrustedDomain(src, targetUrl) {
        const trustedDomains = [
            'googleapis.com',
            'gstatic.com',
            'google.com',
            'googleadservices.com',
            'googlesyndication.com',
            'apple.com',
            'microsoft.com',
            'cloudflare.com',
            'jsdelivr.net',
            'unpkg.com',
            'cdnjs.cloudflare.com',
            'github.com',
            'githubusercontent.com',
            'fbcdn.net',
            'facebook.com',
            'twitter.com',
            'twimg.com'
        ];

        try {
            const scriptUrl = new URL(src);
            const targetUrlObj = new URL(targetUrl);
            
            // Auto-trust first-party scripts
            const scriptRoot = this.extractRootDomain(scriptUrl.hostname);
            const targetRoot = this.extractRootDomain(targetUrlObj.hostname);
            
            if (scriptRoot === targetRoot) return true;

            return trustedDomains.some(domain => scriptUrl.hostname.includes(domain));
        } catch {
            return false;
        }
    }

    /**
     * Extract root domain
     */
    extractRootDomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    }

    /**
     * Check clickjacking protection
     */
    checkClickjackingProtection(headers, doc) {
        // Check X-Frame-Options header
        const xFrameOptions = headers['x-frame-options'];
        if (xFrameOptions) {
            return {
                protected: true,
                method: `X-Frame-Options: ${xFrameOptions}`,
            };
        }

        // Check CSP frame-ancestors
        const csp = headers['content-security-policy'];
        if (csp && csp.includes('frame-ancestors')) {
            return {
                protected: true,
                method: 'CSP frame-ancestors',
            };
        }

        // Check meta tag
        const metaXFrame = doc.querySelector('meta[http-equiv="X-Frame-Options"]');
        if (metaXFrame) {
            return {
                protected: true,
                method: 'Meta X-Frame-Options',
            };
        }

        return {
            protected: false,
            method: null,
        };
    }

    /**
     * Analyze form security
     */
    analyzeFormSecurity(doc) {
        const forms = doc.querySelectorAll('form');

        if (forms.length === 0) {
            return {
                secure: true,
                summary: 'No forms detected',
                hasPasswordField: false,
                message: '',
            };
        }

        let insecureForms = 0;
        let hasPasswordField = false;

        forms.forEach(form => {
            const action = form.action;
            const method = form.method.toLowerCase();

            // Check for password fields
            const passwordInputs = form.querySelectorAll('input[type="password"]');
            if (passwordInputs.length > 0) {
                hasPasswordField = true;
            }

            // Check if form submits to HTTP
            if (action && action.startsWith('http:')) {
                insecureForms++;
            }

            // Check if password form uses GET
            if (passwordInputs.length > 0 && method === 'get') {
                insecureForms++;
            }
        });

        return {
            secure: insecureForms === 0,
            summary: `${forms.length} form(s), ${insecureForms} insecure`,
            hasPasswordField,
            message: insecureForms > 0 ? `${insecureForms} form(s) may submit data insecurely` : '',
        };
    }

    /**
     * Analyze iframes
     */
    analyzeIframes(doc) {
        const iframes = doc.querySelectorAll('iframe');
        let suspicious = 0;

        iframes.forEach(iframe => {
            const src = iframe.src;

            // Check for suspicious patterns
            if (src && src.startsWith('http:')) {
                suspicious++;
            }

            // Check for missing sandbox
            if (!iframe.hasAttribute('sandbox')) {
                suspicious++;
            }
        });

        return {
            total: iframes.length,
            suspicious,
            safe: suspicious === 0,
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
    generateSummary(score, issues) {
        if (score >= 90) {
            return 'Verified script security architecture';
        }
        if (issues.length > 0) {
            // Return the most severe issue message
            const sortedIssues = [...issues].sort((a, b) => {
                const weights = { high: 0, medium: 1, low: 2 };
                return weights[a.severity] - weights[b.severity];
            });
            return sortedIssues[0].message;
        }
        return 'Standard content security profile';
    }
}

export default new ContentSecurityAnalyzer();
