/**
 * OpenSafe - Advertisement Detector
 * Detects ad networks and calculates ad density
 */

// Ad network database
const adNetworks = {
    networks: [
        { name: "Google AdSense", domain: "googlesyndication.com", pattern: "adsbygoogle" },
        { name: "Google AdWords", domain: "googleadservices.com", pattern: "adwords" },
        { name: "DoubleClick", domain: "doubleclick.net", pattern: "doubleclick" },
        { name: "Media.net", domain: "media.net", pattern: "media" },
        { name: "Amazon Ads", domain: "amazon-adsystem.com", pattern: "amazon" },
        { name: "Taboola", domain: "taboola.com", pattern: "taboola" },
        { name: "Outbrain", domain: "outbrain.com", pattern: "outbrain" },
        { name: "AdRoll", domain: "adroll.com", pattern: "adroll" },
        { name: "Criteo", domain: "criteo.com", pattern: "criteo" },
        { name: "AppNexus", domain: "adnxs.com", pattern: "appnexus" },
        { name: "Pubmatic", domain: "pubmatic.com", pattern: "pubmatic" },
        { name: "OpenX", domain: "openx.net", pattern: "openx" },
        { name: "Index Exchange", domain: "indexexchange.com", pattern: "casalemedia" },
        { name: "Rubicon Project", domain: "rubiconproject.com", pattern: "rubicon" },
        { name: "Sovrn", domain: "lijit.com", pattern: "sovrn" }
    ]
};

class AdDetector {
    /**
     * Analyze advertisement presence and density
     * @param {Document} doc - Parsed document
     * @param {string} url - Target URL
     * @returns {object} - Analysis results
     */
    async analyze(doc, url) {
        const checks = [];
        const issues = [];
        const details = [];

        // Check 1: Ad Network Scripts
        const adScripts = this.detectAdNetworks(doc);
        checks.push({
            name: 'Ad Networks',
            passed: adScripts.length === 0,
            weight: 2,
        });

        if (adScripts.length > 0) {
            issues.push({
                severity: adScripts.length > 3 ? 'medium' : 'low',
                message: `${adScripts.length} ad network(s) detected`,
                recommendation: 'Website displays advertisements',
            });
        }

        details.push({
            label: 'Ad Networks',
            value: adScripts.length === 0 ? 'None' : adScripts.map(a => a.name).join(', '),
            status: adScripts.length === 0 ? 'safe' : 'warning',
        });

        // Check 2: Ad Density
        const adDensity = this.calculateAdDensity(doc);
        checks.push({
            name: 'Ad Density',
            passed: adDensity.percentage < 20,
            weight: 2,
        });

        if (adDensity.percentage >= 30) {
            issues.push({
                severity: 'medium',
                message: `High ad density (${adDensity.percentage}%)`,
                recommendation: 'Excessive advertisements may impact user experience',
            });
        }

        details.push({
            label: 'Ad Density',
            value: `${adDensity.percentage}% (${adDensity.adElements}/${adDensity.totalElements})`,
            status: adDensity.percentage < 20 ? 'safe' : adDensity.percentage < 40 ? 'warning' : 'danger',
        });

        // Check 3: Popup/Overlay Ads
        const popups = this.detectPopups(doc);
        checks.push({
            name: 'Popup Ads',
            passed: !popups.detected,
            weight: 1,
        });

        if (popups.detected) {
            issues.push({
                severity: 'low',
                message: 'Popup or overlay ads detected',
                recommendation: 'May display intrusive advertisements',
            });
        }

        details.push({
            label: 'Popups',
            value: popups.detected ? 'Detected' : 'None',
            status: popups.detected ? 'warning' : 'safe',
        });

        // Calculate module score
        const score = this.calculateScore(checks);
        const confidence = 85;

        return {
            score,
            confidence,
            checks,
            issues,
            details,
            summary: this.generateSummary(score, adScripts.length),
            adNetworks: adScripts,
            adDensity,
            popups,
        };
    }

    /**
     * Detect ad network scripts
     */
    detectAdNetworks(doc) {
        const detected = [];
        const scripts = doc.querySelectorAll('script[src]');

        scripts.forEach(script => {
            const src = script.src.toLowerCase();

            for (const network of adNetworks.networks) {
                if (src.includes(network.domain) || src.includes(network.pattern)) {
                    detected.push({
                        name: network.name,
                        domain: network.domain,
                        src: script.src,
                    });
                    break;
                }
            }
        });

        return detected;
    }

    /**
     * Calculate ad density
     */
    calculateAdDensity(doc) {
        const totalElements = doc.querySelectorAll('*').length;
        let adElements = 0;

        // Common ad selectors
        const adSelectors = [
            '[class*="ad-"]',
            '[class*="ads-"]',
            '[id*="ad-"]',
            '[id*="ads-"]',
            '[class*="banner"]',
            '[class*="sponsor"]',
            '[data-ad]',
            'ins.adsbygoogle',
            '.advertisement',
            '#advertisement',
        ];

        adSelectors.forEach(selector => {
            adElements += doc.querySelectorAll(selector).length;
        });

        const percentage = totalElements > 0
            ? Math.round((adElements / totalElements) * 100)
            : 0;

        return {
            adElements,
            totalElements,
            percentage,
        };
    }

    /**
     * Detect popup and overlay ads
     */
    detectPopups(doc) {
        let detected = false;

        // Check for common popup patterns
        const popupSelectors = [
            '[class*="popup"]',
            '[class*="modal"]',
            '[class*="overlay"]',
            '[class*="lightbox"]',
        ];

        for (const selector of popupSelectors) {
            const elements = doc.querySelectorAll(selector);
            elements.forEach(el => {
                // Check if element has ad-related content
                const html = el.innerHTML.toLowerCase();
                if (html.includes('ad') || html.includes('sponsor') || html.includes('advertisement')) {
                    detected = true;
                }
            });
        }

        return {
            detected,
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
    generateSummary(score, adCount) {
        if (score >= 80) {
            return 'Minimal or no advertisements';
        }
        if (score >= 60) {
            return `${adCount} ad network(s) detected`;
        }
        return `Heavy advertising (${adCount} networks)`;
    }
}

export default new AdDetector();
