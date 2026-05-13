/**
 * OpenSafe - Performance & SEO Analyzer
 * Analyzes website performance and SEO best practices
 */

class PerformanceSeoAnalyzer {
    /**
     * Analyze performance and SEO
     * @param {Document} doc - Parsed document
     * @param {string} url - Target URL
     * @returns {object} - Analysis results
     */
    async analyze(doc, url) {
        const checks = [];
        const issues = [];
        const details = [];

        // Check 1: SEO Meta Tags
        const seoMeta = this.analyzeSeoMeta(doc);
        checks.push({
            name: 'SEO Meta Tags',
            passed: seoMeta.score > 0.7,
            weight: 2,
        });

        if (seoMeta.score < 0.7) {
            issues.push({
                severity: 'low',
                message: `Missing ${seoMeta.missing.length} important SEO tag(s)`,
                recommendation: 'Improve SEO by adding missing meta tags',
            });
        }

        details.push({
            label: 'SEO Tags',
            value: `${seoMeta.present}/${seoMeta.total} present`,
            status: seoMeta.score > 0.7 ? 'safe' : 'warning',
        });

        // Check 2: Resource Count
        const resources = this.analyzeResources(doc);
        checks.push({
            name: 'Resource Count',
            passed: resources.total < 100,
            weight: 1,
        });

        if (resources.total >= 150) {
            issues.push({
                severity: 'low',
                message: `High resource count (${resources.total})`,
                recommendation: 'May impact page load performance',
            });
        }

        details.push({
            label: 'Resources',
            value: `${resources.total} (${resources.scripts}js, ${resources.stylesheets}css, ${resources.images}img)`,
            status: resources.total < 100 ? 'safe' : 'warning',
        });

        // Check 3: Mobile Responsiveness
        const responsive = this.checkResponsiveness(doc);
        checks.push({
            name: 'Mobile Responsive',
            passed: responsive.isResponsive,
            weight: 2,
        });

        if (!responsive.isResponsive) {
            issues.push({
                severity: 'low',
                message: 'No mobile viewport meta tag detected',
                recommendation: 'May not display properly on mobile devices',
            });
        }

        details.push({
            label: 'Mobile Responsive',
            value: responsive.isResponsive ? 'Yes' : 'No',
            status: responsive.isResponsive ? 'safe' : 'warning',
        });

        // Check 4: Heading Structure
        const headings = this.analyzeHeadings(doc);
        checks.push({
            name: 'Heading Structure',
            passed: headings.valid,
            weight: 1,
        });

        details.push({
            label: 'Headings',
            value: headings.valid ? 'Proper hierarchy' : 'Issues detected',
            status: headings.valid ? 'safe' : 'warning',
        });

        // Calculate module score
        const score = this.calculateScore(checks);
        const confidence = 70;

        return {
            score,
            confidence,
            checks,
            issues,
            details,
            summary: this.generateSummary(score),
            seoMeta,
            resources,
            responsive,
            headings,
        };
    }

    /**
     * Analyze SEO meta tags
     */
    analyzeSeoMeta(doc) {
        const requiredTags = {
            title: doc.querySelector('title'),
            description: doc.querySelector('meta[name="description"]'),
            viewport: doc.querySelector('meta[name="viewport"]'),
            charset: doc.querySelector('meta[charset]'),
            ogTitle: doc.querySelector('meta[property="og:title"]'),
            ogDescription: doc.querySelector('meta[property="og:description"]'),
        };

        const present = Object.values(requiredTags).filter(tag => tag !== null).length;
        const total = Object.keys(requiredTags).length;
        const missing = Object.keys(requiredTags).filter(key => requiredTags[key] === null);

        return {
            tags: requiredTags,
            present,
            total,
            missing,
            score: present / total,
        };
    }

    /**
     * Analyze resources
     */
    analyzeResources(doc) {
        const scripts = doc.querySelectorAll('script').length;
        const stylesheets = doc.querySelectorAll('link[rel="stylesheet"]').length;
        const images = doc.querySelectorAll('img').length;
        const iframes = doc.querySelectorAll('iframe').length;

        return {
            scripts,
            stylesheets,
            images,
            iframes,
            total: scripts + stylesheets + images + iframes,
        };
    }

    /**
     * Check mobile responsiveness
     */
    checkResponsiveness(doc) {
        const viewport = doc.querySelector('meta[name="viewport"]');

        return {
            isResponsive: viewport !== null,
            viewportContent: viewport ? viewport.getAttribute('content') : null,
        };
    }

    /**
     * Analyze heading structure
     */
    analyzeHeadings(doc) {
        const h1Count = doc.querySelectorAll('h1').length;
        const headings = {
            h1: h1Count,
            h2: doc.querySelectorAll('h2').length,
            h3: doc.querySelectorAll('h3').length,
            h4: doc.querySelectorAll('h4').length,
            h5: doc.querySelectorAll('h5').length,
            h6: doc.querySelectorAll('h6').length,
        };

        // Valid if exactly one H1
        const valid = h1Count === 1;

        return {
            headings,
            valid,
            h1Count,
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
    generateSummary(score) {
        if (score >= 80) {
            return 'Good performance and SEO practices';
        }
        if (score >= 60) {
            return 'Acceptable performance with minor issues';
        }
        return 'Performance and SEO need improvement';
    }
}

export default new PerformanceSeoAnalyzer();
