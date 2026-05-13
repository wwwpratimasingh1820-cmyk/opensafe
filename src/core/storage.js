/**
 * OpenSafe - IndexedDB Storage Layer
 * Handles scan history, cached responses, and user preferences
 */

import { openDB } from 'idb';

const DB_NAME = 'opensafe-db';
const DB_VERSION = 1;

class Storage {
    constructor() {
        this.db = null;
    }

    async init() {
        this.db = await openDB(DB_NAME, DB_VERSION, {
            upgrade(db) {
                // Scan history store
                if (!db.objectStoreNames.contains('scans')) {
                    const scanStore = db.createObjectStore('scans', {
                        keyPath: 'id',
                        autoIncrement: true,
                    });
                    scanStore.createIndex('url', 'url', { unique: false });
                    scanStore.createIndex('timestamp', 'timestamp', { unique: false });
                }

                // Cached responses store
                if (!db.objectStoreNames.contains('cache')) {
                    const cacheStore = db.createObjectStore('cache', {
                        keyPath: 'url',
                    });
                    cacheStore.createIndex('timestamp', 'timestamp', { unique: false });
                }

                // User preferences store
                if (!db.objectStoreNames.contains('preferences')) {
                    db.createObjectStore('preferences', {
                        keyPath: 'key',
                    });
                }
            },
        });
    }

    // Scan History Methods
    async saveScan(scanData) {
        const scan = {
            url: scanData.url,
            score: scanData.score,
            confidence: scanData.confidence,
            results: scanData.results,
            timestamp: Date.now(),
        };
        return await this.db.add('scans', scan);
    }

    async getRecentScans(limit = 5) {
        const tx = this.db.transaction('scans', 'readonly');
        const index = tx.store.index('timestamp');
        const scans = await index.getAll();
        return scans.reverse().slice(0, limit);
    }

    async getScanByUrl(url) {
        const tx = this.db.transaction('scans', 'readonly');
        const index = tx.store.index('url');
        const scans = await index.getAll(url);
        return scans.length > 0 ? scans[scans.length - 1] : null;
    }

    async deleteScan(id) {
        return await this.db.delete('scans', id);
    }

    async clearScans() {
        return await this.db.clear('scans');
    }

    // Cache Methods
    async cacheResponse(url, data) {
        const cache = {
            url,
            data,
            timestamp: Date.now(),
        };
        return await this.db.put('cache', cache);
    }

    async getCachedResponse(url, maxAge = 3600000) { // 1 hour default
        const cached = await this.db.get('cache', url);
        if (!cached) return null;

        const age = Date.now() - cached.timestamp;
        if (age > maxAge) {
            await this.db.delete('cache', url);
            return null;
        }

        return cached.data;
    }

    async clearCache() {
        return await this.db.clear('cache');
    }

    // Preferences Methods
    async setPreference(key, value) {
        return await this.db.put('preferences', { key, value });
    }

    async getPreference(key, defaultValue = null) {
        const pref = await this.db.get('preferences', key);
        return pref ? pref.value : defaultValue;
    }

    async clearAllData() {
        await this.clearScans();
        await this.clearCache();
        await this.db.clear('preferences');
    }
}

export default new Storage();
