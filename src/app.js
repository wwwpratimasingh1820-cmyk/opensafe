/**
 * OpenSafe - Main Application Entry Point
 * Handles UI interactions and coordinates analysis workflow
 */

import './styles/index.css';
import analyzer from './core/analyzer.js';
import storage from './core/storage.js';
import scoringEngine from './utils/scoring.js';
import { escapeHTML } from './utils/sanitizer.js';

class App {
    constructor() {
        this.elements = {};
        this.startTime = null;
        this.timerInterval = null;
        this.adsterraLoaded = false;
    }

    /**
     * Initialize application
     */
    async init() {
        console.log('OpenSafe: Initializing [AetherTech OS]...');

        try {
            // Cache DOM elements first so we can use them
            this.cacheElements();
            console.log('OpenSafe: Elements cached');

            // Set up event listeners immediately
            this.setupEventListeners();
            console.log('OpenSafe: Event listeners attached');
        } catch (e) {
            console.error('OpenSafe: Fatal error during UI initialization:', e);
            // Help the user see what's wrong without opening console
            const errorBanner = document.createElement('div');
            errorBanner.className = 'ui-rescue-banner';
            errorBanner.style = "position:fixed; top:0; left:0; right:0; background:#ef4444; color:white; padding:15px; z-index:10000; text-align:center; font-family:monospace; font-weight:bold; box-shadow: 0 4px 12px rgba(0,0,0,0.5);";
            errorBanner.innerHTML = `⚠️ SYSTEM_ERR: ${e.message}<br><small style="font-weight:normal;opacity:0.8">Check browser console (F12) for detailed trace.</small>`;
            document.body.appendChild(errorBanner);
            return;
        }

        try {
            // Initialize storage
            await storage.init();
            console.log('OpenSafe: Storage initialized');

            // Load recent scans
            await this.loadRecentScans();
            console.log('OpenSafe: Recent scans loaded');
        } catch (error) {
            console.error('OpenSafe: Storage initialization failed:', error);
            // Non-fatal
        }

        // Set up analyzer progress callback
        analyzer.setProgressCallback((progress, status) => {
            this.updateProgress(progress, status);
        });

        console.log('OpenSafe: SYSTEM_READY');
    }

    /**
     * Cache DOM elements
     */
    cacheElements() {
        this.elements = {
            // Input
            urlInput: document.getElementById('urlInput'),
            analyzeBtn: document.getElementById('analyzeBtn'),
            recentScans: document.getElementById('recentScans'),

            // Sections
            heroSection: document.getElementById('heroSection'),
            progressSection: document.getElementById('progressSection'),
            resultsSection: document.getElementById('resultsSection'),

            // Progress
            progressContent: document.getElementById('progressContent'),
            progressBar: document.getElementById('progressBar'),
            progressStatus: document.getElementById('progressStatus'),
            progressTime: document.getElementById('progressTime'),

            // Error
            errorContent: document.getElementById('errorContent'),
            errorMessage: document.getElementById('errorMessage'),
            retryBtn: document.getElementById('retryBtn'),

            // Results: Main
            scoreCircle: document.getElementById('scoreCircle'),
            scoreProgress: document.getElementById('scoreProgress'),
            scoreValue: document.getElementById('scoreValue'),
            analyzedUrl: document.getElementById('analyzedUrl'),
            scoreDescription: document.getElementById('scoreDescription'),
            threatGrid: document.getElementById('threatGrid'),
            detailsContainer: document.getElementById('detailsContainer'),

            // Results: Categories
            securityBar: document.getElementById('securityBar'),
            privacyBar: document.getElementById('privacyBar'),
            reputationBar: document.getElementById('reputationBar'),

            // Buttons
            exportJson: document.getElementById('exportJson'),
            newScan: document.getElementById('newScan'),
            aboutBtn: document.getElementById('aboutBtn'),
            limitationsBtn: document.getElementById('limitationsBtn'),

            // Modals
            aboutModal: document.getElementById('aboutModal'),
            limitationsModal: document.getElementById('limitationsModal'),
            closeAbout: document.getElementById('closeAbout'),
            closeLimitations: document.getElementById('closeLimitations'),
        };

        // Safety check
        for (const [key, el] of Object.entries(this.elements)) {
            if (!el) {
                console.warn(`UI element missing: ${key}`);
                // Only throw for absolutely critical ones
                if (['urlInput', 'analyzeBtn', 'progressSection'].includes(key)) {
                    throw new Error(`Critical UI element missing: ${key}`);
                }
            }
        }
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        // Analyze button
        this.elements.analyzeBtn.addEventListener('click', () => this.startAnalysis());

        // Enter key on input
        this.elements.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.startAnalysis();
            }
        });

        // Export buttons
        this.elements.exportJson.addEventListener('click', () => this.exportJson());
        this.elements.newScan.addEventListener('click', () => this.resetToInput());
        this.elements.retryBtn.addEventListener('click', () => this.resetToInput());

        // Modal buttons
        this.elements.aboutBtn.addEventListener('click', () => this.showModal('about'));
        this.elements.limitationsBtn.addEventListener('click', () => this.showModal('limitations'));
        this.elements.closeAbout.addEventListener('click', () => this.hideModal('about'));
        this.elements.closeLimitations.addEventListener('click', () => this.hideModal('limitations'));

        // Close modals on backdrop click
        this.elements.aboutModal.addEventListener('click', (e) => {
            if (e.target === this.elements.aboutModal) {
                this.hideModal('about');
            }
        });
        this.elements.limitationsModal.addEventListener('click', (e) => {
            if (e.target === this.elements.limitationsModal) {
                this.hideModal('limitations');
            }
        });


        // Browser Back Button Support
        window.addEventListener('popstate', (event) => {
            // If the user navigates back to the root (no state or section: 'input')
            if (!event.state || event.state.section === 'input') {
                this.resetToInput(true); // pass true to indicate it's from history
            }
        });
    }

    /**
     * Load recent scans
     */
    async loadRecentScans() {
        try {
            const scans = await storage.getRecentScans(5);

            if (scans.length === 0) {
                this.elements.recentScans.innerHTML = '';
                return;
            }

            this.elements.recentScans.innerHTML = scans.map(scan => {
                try {
                    const domain = new URL(scan.url).hostname;
                    return `
                        <div class="recent-scan-chip" data-url="${scan.url}" data-id="${scan.id}">
                            <span class="chip-text">${domain}</span>
                            <button class="chip-delete" title="Remove from history">&times;</button>
                        </div>
                    `;
                } catch (e) {
                    return ''; // Skip invalid URLs
                }
            }).join('');

            // Add click listeners
            this.elements.recentScans.querySelectorAll('.recent-scan-chip').forEach(chip => {
                // Main chip click for scan
                chip.addEventListener('click', (e) => {
                    if (e.target.classList.contains('chip-delete')) return;
                    this.elements.urlInput.value = chip.dataset.url;
                    this.startAnalysis();
                });

                // Delete button click
                const deleteBtn = chip.querySelector('.chip-delete');
                deleteBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const scanId = parseInt(chip.dataset.id);
                    await storage.deleteScan(scanId);
                    await this.loadRecentScans();
                });
            });
        } catch (e) {
            console.warn('OpenSafe: Could not load recent scans history:', e);
        }
    }

    /**
     * Start analysis
     */
    async startAnalysis() {
        let url = this.elements.urlInput.value.trim();

        if (!url) {
            this.showError('REQUIRE_TARGET_URL');
            return;
        }

        // basic URL cleaning
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        try {
            new URL(url);
        } catch (e) {
            this.showError('INVALID_TARGET_URL');
            return;
        }

        // Enable Adsterra Popunder
        this.showAdsterraPopunder();

        // Disable input
        this.elements.analyzeBtn.disabled = true;
        this.elements.urlInput.disabled = true;

        // Show progress section
        this.elements.heroSection.classList.add('hidden');
        this.elements.resultsSection.classList.add('hidden');
        this.elements.progressSection.classList.remove('hidden');

        // Push state for browser back button support
        history.pushState({ section: 'results', url: url }, '', `#results?target=${encodeURIComponent(url)}`);

        // Start timer
        this.startTime = Date.now();
        this.timerInterval = setInterval(() => {
            const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
            this.elements.progressTime.textContent = `${elapsed}s`;
        }, 100);

        try {
            // Reset UI state
            this.elements.progressContent.classList.remove('hidden');
            this.elements.errorContent.classList.add('hidden');

            // Run analysis
            const results = await analyzer.analyze(url);

            // Stop timer
            clearInterval(this.timerInterval);

            // Display results
            this.displayResults(results);

            // Reload recent scans
            await this.loadRecentScans();

        } catch (error) {
            clearInterval(this.timerInterval);
            console.error('OpenSafe: Analysis failed:', error);
            this.showError(error.message);
        } finally {
            // Re-enable input
            this.elements.analyzeBtn.disabled = false;
            this.elements.urlInput.disabled = false;
        }
    }

    /**
     * Show error state
     */
    showError(message) {
        this.elements.progressContent.classList.add('hidden');
        this.elements.errorContent.classList.remove('hidden');
        this.elements.errorMessage.textContent = message || 'CORE_EXECUTION_FAILURE';
    }

    /**
     * Update progress
     */
    updateProgress(progress, status) {
        this.elements.progressBar.style.width = `${progress}%`;
        const formattedStatus = status.toUpperCase().replace(/\s/g, '_');
        this.elements.progressStatus.textContent = formattedStatus;

        // Pulse the status on change
        this.elements.progressStatus.style.animation = 'none';
        void this.elements.progressStatus.offsetWidth; // trigger reflow
        this.elements.progressStatus.style.animation = 'dataFlicker 0.3s ease-in-out';
    }

    /**
     * Display results
     */
    displayResults(results) {
        // Hide progress, show results
        this.elements.progressSection.classList.add('hidden');
        this.elements.resultsSection.classList.remove('hidden');

        // Update score
        this.updateScore(results.score);

        // Update URL and description
        this.elements.analyzedUrl.textContent = new URL(results.url).hostname.toUpperCase();
        this.elements.scoreDescription.textContent = results.description;

        // Update Category Bars
        this.updateCategoryBars(results.modules);

        // Update threat matrix
        this.updateThreatMatrix(results.modules);

        // Update details
        this.updateDetails(results.modules);

        // Scroll to results
        this.elements.resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    /**
     * Update score display
     */
    updateScore(score) {
        // Animate score
        let currentScore = 0;
        const increment = score / 50; // 50 frames
        const scoreInterval = setInterval(() => {
            currentScore += increment;
            if (currentScore >= score) {
                currentScore = score;
                clearInterval(scoreInterval);
            }
            this.elements.scoreValue.textContent = Math.round(currentScore);
        }, 20);

        // Update circle progress
        const circumference = 2 * Math.PI * 90; // radius = 90
        const offset = circumference - (score / 100) * circumference;
        this.elements.scoreProgress.style.strokeDashoffset = offset;

        // Update color based on score
        const color = scoringEngine.getScoreColor(score);
        this.elements.scoreProgress.style.stroke = color;
    }

    /**
     * Update Category Bars
     */
    updateCategoryBars(modules) {
        // Security aggregate (SSL + Phishing + Content)
        const security = Math.round((modules.ssl.score * 0.4) + (modules.phishing.score * 0.3) + (modules.contentSecurity.score * 0.3));
        const privacy = modules.privacy.score;
        const reputation = modules.phishing.score;

        this.elements.securityBar.style.width = `${security}%`;
        this.elements.privacyBar.style.width = `${privacy}%`;
        this.elements.reputationBar.style.width = `${reputation}%`;

        // Adjust colors
        this.elements.securityBar.style.background = scoringEngine.getScoreColor(security);
        this.elements.privacyBar.style.background = scoringEngine.getScoreColor(privacy);
        this.elements.reputationBar.style.background = scoringEngine.getScoreColor(reputation);
    }

    /**
     * Update threat matrix
     */
    updateThreatMatrix(modules) {
        const threats = [
            { name: 'SSL Security', icon: '🔒', module: 'ssl' },
            { name: 'Core Vulnerabilities', icon: '🛡️', module: 'contentSecurity' },
            { name: 'Privacy Analysis', icon: '👁️', module: 'privacy' },
            { name: 'Phishing Detection', icon: '🎣', module: 'phishing' },
            { name: 'Ad Density', icon: '📢', module: 'ads' },
            { name: 'Performance Metrics', icon: '⚡', module: 'performance' },
        ];

        this.elements.threatGrid.innerHTML = threats.map(threat => {
            const moduleData = modules[threat.module];
            const status = moduleData.score >= 80 ? 'safe' : moduleData.score >= 60 ? 'warn' : 'danger';

            return `
        <div class="threat-card" data-module="${threat.module}">
          <div class="threat-card-header">
            <span class="threat-icon">${threat.icon}</span>
            <span class="status-dot ${status}"></span>
          </div>
          <h4 class="threat-title">${threat.name}</h4>
          <p class="threat-summary">${moduleData.summary}</p>
        </div>
      `;
        }).join('');

        // Add click listeners to expand details
        this.elements.threatGrid.querySelectorAll('.threat-card').forEach(card => {
            card.addEventListener('click', () => {
                const moduleName = card.dataset.module;
                const detailSection = document.querySelector(`[data-detail-module="${moduleName}"]`);
                if (detailSection) {
                    detailSection.scrollIntoView({ behavior: 'smooth' });
                    detailSection.classList.add('expanded');
                }
            });
        });
    }

    /**
     * Update details sections
     */
    updateDetails(modules) {
        const moduleNames = {
            ssl: 'Encryption & SSL Audit',
            contentSecurity: 'Core Vulnerability Scan',
            privacy: 'Privacy & Tracker Metrics',
            phishing: 'Domain Reputation Rank',
            ads: 'Advertisement Density',
            performance: 'System Speed & SEO',
        };

        this.elements.detailsContainer.innerHTML = Object.entries(modules).map(([key, data]) => {
            const safeModuleName = escapeHTML(moduleNames[key] || key);
            return `
        <div class="detail-section" data-detail-module="${key}">
          <div class="detail-header">
            <h4 class="detail-title">${safeModuleName}</h4>
            <span class="detail-expand">▼</span>
          </div>
          <div class="detail-body">
            <div class="detail-content">
              ${data.details.map(detail => `
                <div class="detail-item">
                  <span class="detail-item-label">${escapeHTML(detail.label)}</span>
                  <span class="detail-item-value">${escapeHTML(detail.value)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      `;
        }).join('');

        // Add click listeners for expand/collapse
        this.elements.detailsContainer.querySelectorAll('.detail-header').forEach(header => {
            header.addEventListener('click', () => {
                header.parentElement.classList.toggle('expanded');
            });
        });
    }

    /**
     * Export as JSON
     */
    exportJson() {
        try {
            analyzer.exportAsJson();
        } catch (error) {
            alert(error.message);
        }
    }

    /**
     * Reset to input
     * @param {boolean} fromHistory - Whether this was triggered by browser navigation
     */
    resetToInput(fromHistory = false) {
        this.elements.progressSection.classList.add('hidden');
        this.elements.resultsSection.classList.add('hidden');
        this.elements.heroSection.classList.remove('hidden');

        if (!fromHistory) {
            // If the user clicked the button manually, ensure we update history to root
            history.pushState({ section: 'input' }, '', window.location.pathname);
        }

        // Re-trigger entrance animation
        this.elements.heroSection.style.animation = 'none';
        void this.elements.heroSection.offsetWidth;
        this.elements.heroSection.style.animation = 'fadeInUp 0.8s ease-out forwards';

        this.elements.urlInput.value = '';
        this.elements.urlInput.focus();
    }

    /**
     * Show modal
     */
    showModal(type) {
        if (type === 'about') {
            this.elements.aboutModal.classList.remove('hidden');
            this.elements.aboutModal.classList.add('active');
        } else if (type === 'limitations') {
            this.elements.limitationsModal.classList.remove('hidden');
            this.elements.limitationsModal.classList.add('active');
        }
        document.body.style.overflow = 'hidden'; // Prevent scroll
    }

    /**
     * Hide modal
     */
    hideModal(type) {
        if (type === 'about') {
            this.elements.aboutModal.classList.add('hidden');
            this.elements.aboutModal.classList.remove('active');
        } else if (type === 'limitations') {
            this.elements.limitationsModal.classList.add('hidden');
            this.elements.limitationsModal.classList.remove('active');
        }
        document.body.style.overflow = ''; // Restore scroll
    }

    /**
     * Dynamically load Adsterra Popunder script
     */
    showAdsterraPopunder() {
        if (!this.adsterraLoaded) {
            console.log('OpenSafe: Loading monetization vector...');
            const script = document.createElement('script');
            script.src = 'https://pl29435292.profitablecpmratenetwork.com/c2/3b/fc/c23bfc92667f609485d2a178028154a6.js';
            script.async = true;
            document.body.appendChild(script);
            this.adsterraLoaded = true;
        }
    }
}

// Initialize app when DOM is ready
const startApp = () => {
    try {
        const app = new App();
        app.init();
    } catch (e) {
        console.error('OpenSafe: Failed to start application:', e);
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startApp);
} else {
    startApp();
}

// Global error handler
window.onerror = function (message, source, lineno, colno, error) {
    console.error('OpenSafe SYSTEM_FAULT:', message, 'at', source, lineno, colno);
    return false;
};

window.onunhandledrejection = function (event) {
    console.error('OpenSafe ASYNC_FAULT:', event.reason);
};
