/**
 * OpenSafe - Privacy & Tracker Detector
 * Detects third-party trackers, cookies, and privacy concerns
 */

// Tracker database
const trackerData = {
    trackers: [
        { name: "Google Analytics", domain: "google-analytics.com", pattern: "analytics", category: "Analytics" },
        { name: "Google Tag Manager", domain: "googletagmanager.com", pattern: "gtm", category: "Analytics" },
        { name: "Facebook Pixel", domain: "facebook.net", pattern: "fbevents", category: "Social" },
        { name: "Hotjar", domain: "hotjar.com", pattern: "hotjar", category: "Analytics" },
        { name: "Mixpanel", domain: "mixpanel.com", pattern: "mixpanel", category: "Analytics" },
        { name: "Segment", domain: "segment.com", pattern: "segment", category: "Analytics" },
        { name: "Amplitude", domain: "amplitude.com", pattern: "amplitude", category: "Analytics" },
        { name: "Heap Analytics", domain: "heapanalytics.com", pattern: "heap", category: "Analytics" },
        { name: "Crazy Egg", domain: "crazyegg.com", pattern: "crazyegg", category: "Analytics" },
        { name: "Mouseflow", domain: "mouseflow.com", pattern: "mouseflow", category: "Analytics" },
        { name: "FullStory", domain: "fullstory.com", pattern: "fullstory", category: "Analytics" },
        { name: "Intercom", domain: "intercom.io", pattern: "intercom", category: "Customer Support" },
        { name: "Drift", domain: "drift.com", pattern: "drift", category: "Customer Support" },
        { name: "Zendesk", domain: "zendesk.com", pattern: "zendesk", category: "Customer Support" },
        { name: "LiveChat", domain: "livechatinc.com", pattern: "livechat", category: "Customer Support" }
    ]
};

class PrivacyTrackerAnalyzer {
    /**
     * Analyze privacy and tracking
     * @param {Document} doc - Parsed document
     * @param {string} url - Target URL
     * @returns {object} - Analysis results
     */
    async analyze(doc, url) {
        const checks = [];
        const issues = [];
        const details = [];

        // Check 1: Third-Party Scripts
        const thirdPartyScripts = this.detectThirdPartyScripts(doc, url);
        const trackerScripts = this.identifyTrackers(thirdPartyScripts);

        checks.push({
            name: 'Third-Party Trackers',
            passed: trackerScripts.length === 0,
            weight: 3,
        });

        if (trackerScripts.length > 0) {
            issues.push({
                severity: trackerScripts.length > 5 ? 'high' : 'medium',
                message: `${trackerScripts.length} tracking script(s) detected`,
                recommendation: 'Website tracks user behavior',
            });
        }

        details.push({
            label: 'Trackers',
            value: trackerScripts.length === 0 ? 'None detected' : `${trackerScripts.length} found`,
            status: trackerScripts.length === 0 ? 'safe' : trackerScripts.length > 5 ? 'danger' : 'warning',
        });

        // Check 2: Cookies
        const cookies = this.analyzeCookies();
        checks.push({
            name: 'Cookie Usage',
            passed: cookies.total < 5,
            weight: 1,
        });

        details.push({
            label: 'Cookies',
            value: `${cookies.total} cookie(s)`,
            status: cookies.total < 5 ? 'safe' : cookies.total < 15 ? 'warning' : 'danger',
        });

        // Check 3: LocalStorage/SessionStorage
        const storage = this.analyzeStorage();
        checks.push({
            name: 'Browser Storage',
            passed: storage.items < 10,
            weight: 1,
        });

        details.push({
            label: 'Storage Items',
            value: `${storage.items} item(s)`,
            status: storage.items < 10 ? 'safe' : 'warning',
        });

        // Check 4: Social Media Widgets
        const socialWidgets = this.detectSocialWidgets(doc);
        checks.push({
            name: 'Social Media Tracking',
            passed: socialWidgets.length === 0,
            weight: 2,
        });

        if (socialWidgets.length > 0) {
            issues.push({
                severity: 'low',
                message: `${socialWidgets.length} social media widget(s) detected`,
                recommendation: 'Social widgets may track across websites',
            });
        }

        details.push({
            label: 'Social Widgets',
            value: socialWidgets.length === 0 ? 'None' : socialWidgets.join(', '),
            status: socialWidgets.length === 0 ? 'safe' : 'warning',
        });

        // Check 5: Fingerprinting Detection
        const fingerprinting = this.detectFingerprinting(doc);
        checks.push({
            name: 'Fingerprinting',
            passed: !fingerprinting.detected,
            weight: 2,
        });

        if (fingerprinting.detected) {
            issues.push({
                severity: 'medium',
                message: 'Browser fingerprinting detected',
                recommendation: 'Website may track you without cookies',
            });
        }

        details.push({
            label: 'Fingerprinting',
            value: fingerprinting.detected ? fingerprinting.methods.join(', ') : 'Not detected',
            status: fingerprinting.detected ? 'warning' : 'safe',
        });

        // Calculate module score
        const score = this.calculateScore(checks);
        const confidence = 90; // High confidence for tracker detection

        return {
            score,
            confidence,
            checks,
            issues,
            details,
            summary: this.generateSummary(score, trackerScripts),
            trackers: trackerScripts,
            cookies,
            storage,
            socialWidgets,
            fingerprinting,
        };
    }

    /**
     * Detect third-party scripts
     */
    detectThirdPartyScripts(doc, url) {
        const urlObj = new URL(url);
        const mainDomain = this.extractDomain(urlObj.hostname);
        const thirdParty = [];

        doc.querySelectorAll('script[src]').forEach(script => {
            try {
                const scriptUrl = new URL(script.src);
                const scriptDomain = this.extractDomain(scriptUrl.hostname);

                if (scriptDomain !== mainDomain) {
                    thirdParty.push({
                        src: script.src,
                        domain: scriptDomain,
                    });
                }
            } catch (e) {
                // Invalid URL, skip
            }
        });

        return thirdParty;
    }

    /**
     * Identify known trackers
     */
    identifyTrackers(scripts) {
        const trackers = [];

        for (const script of scripts) {
            for (const tracker of trackerData.trackers) {
                if (script.domain.includes(tracker.domain) || script.src.includes(tracker.pattern)) {
                    trackers.push({
                        ...script,
                        name: tracker.name,
                        category: tracker.category,
                    });
                    break;
                }
            }
        }

        return trackers;
    }

    /**
     * Analyze cookies
     */
    analyzeCookies() {
        const cookies = document.cookie.split(';').filter(c => c.trim());

        return {
            total: cookies.length,
            list: cookies.map(c => {
                const [name] = c.trim().split('=');
                return name;
            }),
        };
    }

    /**
     * Analyze browser storage
     */
    analyzeStorage() {
        let items = 0;

        try {
            items += localStorage.length;
            items += sessionStorage.length;
        } catch (e) {
            // Storage access denied
        }

        return {
            items,
            localStorage: localStorage.length || 0,
            sessionStorage: sessionStorage.length || 0,
        };
    }

    /**
     * Detect social media widgets
     */
    detectSocialWidgets(doc) {
        const widgets = [];
        const patterns = [
            { name: 'Facebook', selector: '[class*="fb-"], [id*="facebook"]' },
            { name: 'Twitter', selector: '[class*="twitter"], [data-tweet-id]' },
            { name: 'LinkedIn', selector: '[class*="linkedin"]' },
            { name: 'Instagram', selector: '[class*="instagram"]' },
            { name: 'Pinterest', selector: '[class*="pinterest"]' },
        ];

        for (const { name, selector } of patterns) {
            if (doc.querySelector(selector)) {
                widgets.push(name);
            }
        }

        // Check for social share scripts
        const scripts = doc.querySelectorAll('script[src]');
        scripts.forEach(script => {
            const src = script.src.toLowerCase();
            if (src.includes('facebook.com') && !widgets.includes('Facebook')) widgets.push('Facebook');
            if (src.includes('twitter.com') && !widgets.includes('Twitter')) widgets.push('Twitter');
            if (src.includes('linkedin.com') && !widgets.includes('LinkedIn')) widgets.push('LinkedIn');
        });

        return widgets;
    }

    /**
     * Detect fingerprinting techniques
     */
    detectFingerprinting(doc) {
        const methods = [];
        const scripts = doc.querySelectorAll('script');

        scripts.forEach(script => {
            const content = script.textContent.toLowerCase();

            // Canvas fingerprinting
            if (content.includes('canvas') && content.includes('todataurl')) {
                methods.push('Canvas');
            }

            // WebGL fingerprinting
            if (content.includes('webgl') || content.includes('getparameter')) {
                methods.push('WebGL');
            }

            // Font fingerprinting
            if (content.includes('font') && content.includes('measuretext')) {
                methods.push('Font');
            }

            // Audio fingerprinting
            if (content.includes('audiocontext') || content.includes('oscillator')) {
                methods.push('Audio');
            }
        });

        return {
            detected: methods.length > 0,
            methods: [...new Set(methods)],
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
    generateSummary(score, trackers) {
        if (score >= 90) {
            return 'No significant tracking detected';
        }
        if (trackers.length > 0) {
            const names = trackers.slice(0, 2).map(t => t.name).join(' and ');
            const extra = trackers.length > 2 ? ` and ${trackers.length - 2} others` : '';
            return `${names}${extra} identified`;
        }
        return 'Standard privacy profile';
    }
}

export default new PrivacyTrackerAnalyzer();
