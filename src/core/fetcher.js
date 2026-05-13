/**
 * OpenSafe - Website Fetcher
 * Handles fetching websites with CORS proxy fallbacks
 */

class Fetcher {
    constructor() {
        // Public CORS proxies (fallback chain)
        this.corsProxies = [
            'https://api.allorigins.win/raw?url=',
            'https://corsproxy.io/?',
            'https://api.codetabs.com/v1/proxy?quest=',
        ];
        this.currentProxyIndex = 0;
        this.timeout = 15000; // 15 seconds
    }

    /**
     * Fetch website with CORS proxy fallback
     * @param {string} url - Target URL
     * @returns {Promise<{html: string, headers: object}>}
     */
    async fetch(url) {
        // Validate URL
        if (!this.isValidUrl(url)) {
            throw new Error('Invalid URL format');
        }

        // Normalize URL
        const normalizedUrl = this.normalizeUrl(url);

        // Try direct fetch first (will work if target has CORS enabled)
        try {
            const response = await this.fetchWithTimeout(normalizedUrl);
            if (response.ok) {
                const html = await response.text();
                const headers = this.extractHeaders(response);
                return { html, headers, url: normalizedUrl };
            }
        } catch (error) {
            console.log('Direct fetch failed, trying CORS proxies...', error.message);
        }

        // Try CORS proxies
        for (let i = 0; i < this.corsProxies.length; i++) {
            try {
                const proxyUrl = this.corsProxies[i] + encodeURIComponent(normalizedUrl);
                console.log(`OpenSafe: REDIRECTING_VIA_SECURE_PROXY_${i + 1}...`);

                // Use a shorter timeout for individual proxies
                const response = await this.fetchWithTimeout(proxyUrl, 8000);

                if (response.ok) {
                    const html = await response.text();
                    const headers = this.extractHeaders(response);
                    console.log(`OpenSafe: PROXY_${i + 1}_ESTABLISHED`);
                    return {
                        html,
                        headers,
                        url: normalizedUrl,
                        proxyUsed: true,
                        proxyIndex: i + 1
                    };
                } else {
                    console.warn(`OpenSafe: PROXY_${i + 1}_REJECTED (Status: ${response.status})`);
                }
            } catch (error) {
                console.warn(`OpenSafe: PROXY_${i + 1}_FAULT:`, error.message);
                continue;
            }
        }

        throw new Error('This website could not be reached. It may not exist, or it is blocking analysis. Please check the URL and try again.');
    }

    /**
     * Fetch with timeout
     */
    async fetchWithTimeout(url, customTimeout) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), customTimeout || this.timeout);

        try {
            console.log(`Fetching: ${url}`);
            const response = await fetch(url, {
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            console.error(`Fetch error for ${url}:`, error);
            throw error;
        }
    }

    /**
     * Extract headers from response
     */
    extractHeaders(response) {
        const headers = {};
        response.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
        });
        return headers;
    }

    /**
     * Validate URL format
     */
    isValidUrl(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Normalize URL (add https if missing)
     */
    normalizeUrl(url) {
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return 'https://' + url;
        }
        return url;
    }

    /**
     * Extract domain from URL
     */
    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return null;
        }
    }
}

export default new Fetcher();
