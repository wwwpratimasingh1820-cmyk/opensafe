/**
 * OpenSafe - Central Analyzer
 * Orchestrates all security analysis modules
 */

import fetcher from './fetcher.js';
import storage from './storage.js';
import domParser from '../utils/dom-parser.js';
import scoringEngine from '../utils/scoring.js';

import sslAnalyzer from '../modules/ssl-analyzer.js';
import contentSecurityAnalyzer from '../modules/content-security.js';
import privacyTrackerAnalyzer from '../modules/privacy-tracker.js';
import phishingDetector from '../modules/phishing-detector.js';
import adDetector from '../modules/ad-detector.js';
import performanceSeoAnalyzer from '../modules/performance-seo.js';

class Analyzer {
    constructor() {
        this.currentAnalysis = null;
        this.progressCallback = null;
    }

    /**
     * Set progress callback
     * @param {Function} callback - Progress callback (progress, status)
     */
    setProgressCallback(callback) {
        this.progressCallback = callback;
    }

    /**
     * Update progress
     */
    updateProgress(progress, status) {
        if (this.progressCallback) {
            this.progressCallback(progress, status);
        }
    }

    /**
     * Analyze website
     * @param {string} url - Target URL
     * @returns {Promise<object>} - Analysis results
     */
    async analyze(url) {
        const startTime = Date.now();
        const ANALYSIS_TIMEOUT = 60000; // 60 seconds global timeout

        // Wrap the entire analysis to handle global timeout
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Analysis timed out. Try a different URL or check your connection.')), ANALYSIS_TIMEOUT);
        });

        const analysisPromise = (async () => {
            try {
                // Step 1: Fetch website (0-20%)
                this.updateProgress(0, 'Connecting to website...');
                const fetchResult = await fetcher.fetch(url);
                const { html, headers, url: normalizedUrl, proxyUsed } = fetchResult;

                if (proxyUsed) {
                    this.updateProgress(10, 'ROUTING_VIA_SECURE_PROXY...');
                }

                this.updateProgress(20, 'Website connection established');

                // Step 2: Parse HTML (20-30%)
                this.updateProgress(20, 'Analyzing structure...');
                const doc = domParser.parse(html);
                this.updateProgress(30, 'Structure analysis complete');

                // Step 3: Run all analysis modules (30-90%)
                const results = {};

                // SSL/TLS Analysis (30-40%)
                console.log('Step 3a: SSL Analysis...');
                this.updateProgress(30, 'Verifying security certificates...');
                results.ssl = await sslAnalyzer.analyze(normalizedUrl, headers, doc);
                this.updateProgress(40, 'Certificate verification complete');

                // Content Security (40-50%)
                console.log('Step 3b: Content Security...');
                this.updateProgress(40, 'Scanning for script vulnerabilities...');
                results.contentSecurity = await contentSecurityAnalyzer.analyze(doc, headers, normalizedUrl);
                this.updateProgress(50, 'Vulnerability scan complete');

                // Privacy & Trackers (50-60%)
                console.log('Step 3c: Privacy...');
                this.updateProgress(50, 'Identifying privacy trackers...');
                results.privacy = await privacyTrackerAnalyzer.analyze(doc, normalizedUrl);
                this.updateProgress(60, 'Privacy analysis complete');

                // Phishing Detection (60-70%)
                console.log('Step 3d: Phishing...');
                this.updateProgress(60, 'Evaluating reputation signals...');
                results.phishing = await phishingDetector.analyze(normalizedUrl, doc);
                this.updateProgress(70, 'Reputation analysis complete');

                // Advertisement Detection (70-80%)
                console.log('Step 3e: Ads...');
                this.updateProgress(70, 'Calculating advertisement density...');
                results.ads = await adDetector.analyze(doc, normalizedUrl);
                this.updateProgress(80, 'Density calculation complete');

                // Performance & SEO (80-90%)
                console.log('Step 3f: Performance...');
                this.updateProgress(80, 'Measuring performance metrics...');
                results.performance = await performanceSeoAnalyzer.analyze(doc, normalizedUrl);
                this.updateProgress(90, 'Performance analysis complete');

                // Step 4: Calculate overall score (90-100%)
                console.log('Step 4: Scoring...');
                this.updateProgress(90, 'Finalizing safety rating...');
                const overallScore = scoringEngine.calculateScore(results);
                this.updateProgress(100, 'All checks complete');

                // Calculate analysis time
                const analysisTime = ((Date.now() - startTime) / 1000).toFixed(1);

                // Compile final results
                const finalResults = {
                    url: normalizedUrl,
                    timestamp: Date.now(),
                    analysisTime,
                    score: overallScore.score,
                    confidence: overallScore.confidence,
                    level: overallScore.level,
                    description: overallScore.description,
                    modules: results,
                    summary: this.generateSummary(results),
                };

                // Save to storage
                try {
                    await storage.saveScan(finalResults);
                } catch (sError) {
                    console.warn('Could not save scan to history:', sError);
                }

                this.currentAnalysis = finalResults;
                return finalResults;

            } catch (error) {
                console.error('Core analysis error:', error);
                throw error;
            }
        })();

        return Promise.race([analysisPromise, timeoutPromise]);
    }

    /**
     * Generate summary of all findings
     */
    generateSummary(results) {
        const allIssues = [];
        const allDetails = [];

        for (const [moduleName, moduleResult] of Object.entries(results)) {
            if (moduleResult.issues) {
                allIssues.push(...moduleResult.issues.map(issue => ({
                    ...issue,
                    module: moduleName,
                })));
            }
            if (moduleResult.details) {
                allDetails.push(...moduleResult.details.map(detail => ({
                    ...detail,
                    module: moduleName,
                })));
            }
        }

        // Sort issues by severity
        const severityOrder = { high: 0, medium: 1, low: 2 };
        allIssues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        return {
            totalIssues: allIssues.length,
            highSeverity: allIssues.filter(i => i.severity === 'high').length,
            mediumSeverity: allIssues.filter(i => i.severity === 'medium').length,
            lowSeverity: allIssues.filter(i => i.severity === 'low').length,
            issues: allIssues,
            details: allDetails,
        };
    }

    /**
     * Get current analysis
     */
    getCurrentAnalysis() {
        return this.currentAnalysis;
    }

    /**
     * Export results as JSON
     */
    exportAsJson() {
        if (!this.currentAnalysis) {
            throw new Error('No analysis available to export');
        }

        const json = JSON.stringify(this.currentAnalysis, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `opensafe-analysis-${Date.now()}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }
}

export default new Analyzer();
