/**
 * VirusTotal Scanner Module
 * Scans packages for malicious code using VirusTotal API v3
 */

import fetch from 'node-fetch';

export class VirusTotalScanner {
  constructor(config) {
    this.apiKey = config.virustotal.apiKey || process.env.VIRUSTOTAL_API_KEY;
    this.baseUrl = config.virustotal.baseUrl;
    this.timeout = config.virustotal.timeoutMs;
    
    if (!this.apiKey) {
      throw new Error('VirusTotal API key is required (VIRUSTOTAL_API_KEY)');
    }
  }

  /**
   * Scan a package URL or hash
   * @param {string} target - URL or file hash
   * @returns {Promise<Object>} Scan results
   */
  async scan(target) {
    try {
      // Check if target is a URL or hash
      const isUrl = target.startsWith('http://') || target.startsWith('https://');
      
      if (isUrl) {
        return await this.scanUrl(target);
      } else {
        return await this.getFileReport(target);
      }
    } catch (error) {
      return {
        success: false,
        error: error.message,
        maliciousVotes: 0,
        suspiciousVotes: 0
      };
    }
  }

  /**
   * Scan a URL
   * @param {string} url - URL to scan
   * @returns {Promise<Object>} Scan results
   */
  async scanUrl(url) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      // Submit URL for scanning
      const scanResponse = await fetch(`${this.baseUrl}/urls`, {
        method: 'POST',
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`,
        signal: controller.signal
      });

      if (!scanResponse.ok) {
        throw new Error(`VirusTotal API error: ${scanResponse.status}`);
      }

      const scanData = await scanResponse.json();
      const analysisId = scanData.data.id;

      // Wait a bit for analysis
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Get analysis results
      const resultResponse = await fetch(`${this.baseUrl}/analyses/${analysisId}`, {
        headers: { 'x-apikey': this.apiKey },
        signal: controller.signal
      });

      if (!resultResponse.ok) {
        throw new Error(`VirusTotal API error: ${resultResponse.status}`);
      }

      const resultData = await resultResponse.json();
      return this.parseResults(resultData);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Get file report by hash
   * @param {string} hash - File hash (SHA256, SHA1, or MD5)
   * @returns {Promise<Object>} Report results
   */
  async getFileReport(hash) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/files/${hash}`, {
        headers: { 'x-apikey': this.apiKey },
        signal: controller.signal
      });

      if (response.status === 404) {
        return {
          success: true,
          found: false,
          maliciousVotes: 0,
          suspiciousVotes: 0
        };
      }

      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.status}`);
      }

      const data = await response.json();
      return this.parseResults(data);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Parse VirusTotal API results
   * @param {Object} data - Raw API response
   * @returns {Object} Parsed results
   */
  parseResults(data) {
    const stats = data.data?.attributes?.last_analysis_stats || 
                  data.data?.attributes?.stats || {};
    
    return {
      success: true,
      found: true,
      maliciousVotes: stats.malicious || 0,
      suspiciousVotes: stats.suspicious || 0,
      undetectedVotes: stats.undetected || 0,
      harmlessVotes: stats.harmless || 0,
      totalEngines: Object.values(stats).reduce((sum, val) => sum + val, 0),
      details: data.data?.attributes
    };
  }
}
