/**
 * OpenSafe - Safety Score Calculator
 * Calculates aggregate safety score from module results
 */

class ScoringEngine {
    constructor() {
        // Weight distribution (must sum to 1.0)
        // Prioritizing Core Security to prevent false "Moderate" ratings for safe sites like YouTube
        this.weights = {
            ssl: 0.30,           // SSL/TLS security
            phishing: 0.25,      // Phishing indicators
            contentSecurity: 0.20, // XSS, clickjacking, etc.
            privacy: 0.15,       // Trackers, cookies
            ads: 0.05,           // Advertisement density
            performance: 0.05,   // Performance/SEO
        };
    }

    /**
     * Calculate overall safety score
     * @param {object} results - Results from all modules
     * @returns {object} - {score, confidence, description, level}
     */
    calculateScore(results) {
        let totalScore = 0;
        let totalWeight = 0;
        let confidenceSum = 0;
        let confidenceCount = 0;

        let primaryConcernModule = null;
        let minModuleScore = 101;

        // Calculate weighted score
        for (const [module, weight] of Object.entries(this.weights)) {
            if (results[module]) {
                const moduleResult = results[module];
                totalScore += moduleResult.score * weight;
                totalWeight += weight;

                if (moduleResult.score < minModuleScore) {
                    minModuleScore = moduleResult.score;
                    primaryConcernModule = module;
                }

                if (moduleResult.confidence !== undefined) {
                    confidenceSum += moduleResult.confidence;
                    confidenceCount++;
                }
            }
        }

        // Normalize score to 0-100
        const score = totalWeight > 0 ? Math.round(totalScore / totalWeight) : 0;

        // Calculate average confidence
        const confidence = confidenceCount > 0
            ? Math.round(confidenceSum / confidenceCount)
            : 50;

        // Determine threat level and description
        const primaryConcern = results[primaryConcernModule];
        const { level, description } = this.getScoreLevel(score, results, primaryConcern);

        return {
            score,
            confidence,
            level,
            description,
            primaryConcern: primaryConcernModule
        };
    }

    /**
     * Get threat level and description based on score
     */
    getScoreLevel(score, results, primaryConcern) {
        const concernMsg = primaryConcern && primaryConcern.score < 90 
            ? ` Concern detected: ${primaryConcern.summary}.` 
            : '';

        if (score >= 90) {
            return {
                level: 'safe',
                description: 'Verified safe domain. All core security protocols are active and script integrity is confirmed.',
            };
        } else if (score >= 80) {
            return {
                level: 'safe',
                description: `This website is mathematically secure.${concernMsg}`,
            };
        } else if (score >= 60) {
            return {
                level: 'moderate',
                description: `Analysis suggests a functional site, but risks exist.${concernMsg}`,
            };
        } else if (score >= 40) {
            return {
                level: 'warning',
                description: `Significant security risks identified.${concernMsg}`,
            };
        } else {
            return {
                level: 'danger',
                description: `CRITICAL: Severe vulnerabilities or phishing detected. Avoid interaction.${concernMsg}`,
            };
        }
    }

    /**
     * Calculate module score from individual checks
     * @param {array} checks - Array of check results {passed: boolean, weight: number}
     * @returns {number} - Score 0-100
     */
    calculateModuleScore(checks) {
        if (!checks || checks.length === 0) return 100;

        let totalWeight = 0;
        let passedWeight = 0;

        for (const check of checks) {
            const weight = check.weight || 1;
            totalWeight += weight;
            if (check.passed) {
                passedWeight += weight;
            }
        }

        return totalWeight > 0 ? Math.round((passedWeight / totalWeight) * 100) : 100;
    }

    /**
     * Get color for score
     */
    getScoreColor(score) {
        if (score >= 80) return '#10b981'; // Green
        if (score >= 60) return '#f59e0b'; // Yellow
        if (score >= 40) return '#fb923c'; // Orange
        return '#ef4444'; // Red
    }

    /**
     * Get confidence level label
     */
    getConfidenceLabel(confidence) {
        if (confidence >= 80) return 'High';
        if (confidence >= 60) return 'Medium';
        return 'Low';
    }
}

export default new ScoringEngine();
