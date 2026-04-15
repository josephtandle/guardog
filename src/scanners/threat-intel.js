/**
 * Threat Intelligence Feed Module
 * Pulls from free public threat feeds and normalizes findings
 * Sources: OSV, NVD, CISA KEV, GitHub Advisories
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fetch from 'node-fetch';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '../../data');
const CACHE_DIR = join(DATA_DIR, 'cache');
const CACHE_PATH = join(CACHE_DIR, 'threat-intel-cache.json');
const CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

export class ThreatIntel {
  constructor(config = {}) {
    this.config = config;
    this.githubToken = process.env.GITHUB_TOKEN || null;
    this.timeout = config.timeoutMs || 15000;

    // Ensure data directories exist
    for (const dir of [DATA_DIR, CACHE_DIR]) {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  /**
   * Load cache from disk
   * @returns {Object|null} Cached data or null if stale/missing
   */
  loadCache() {
    try {
      if (!existsSync(CACHE_PATH)) return null;
      const cache = JSON.parse(readFileSync(CACHE_PATH, 'utf-8'));
      const age = Date.now() - (cache.fetchedAt || 0);
      if (age > CACHE_TTL_MS) {
        console.log('[ThreatIntel] Cache expired, will refresh');
        return null;
      }
      console.log(`[ThreatIntel] Using cached data (${Math.round(age / 60000)}m old)`);
      return cache;
    } catch {
      return null;
    }
  }

  /**
   * Save cache to disk
   * @param {Object} data - Data to cache
   */
  saveCache(data) {
    try {
      writeFileSync(CACHE_PATH, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error('[ThreatIntel] Failed to save cache:', err.message);
    }
  }

  /**
   * Fetch with timeout and error handling
   * @param {string} url - URL to fetch
   * @param {Object} options - fetch options
   * @returns {Promise<Response>}
   */
  async safeFetch(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Query OSV (Open Source Vulnerabilities) for a specific package
   * @param {string} packageName - Package name
   * @param {string} ecosystem - 'npm' or 'PyPI'
   * @returns {Promise<Array>} Normalized findings
   */
  async queryOSV(packageName, ecosystem = 'npm') {
    const ecosystemMap = { npm: 'npm', pypi: 'PyPI' };
    const body = {
      package: {
        name: packageName,
        ecosystem: ecosystemMap[ecosystem] || ecosystem
      }
    };

    try {
      const response = await this.safeFetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      if (!response.ok) return [];

      const data = await response.json();
      return (data.vulns || []).map(vuln => this.normalizeOSV(vuln, packageName, ecosystem));
    } catch (err) {
      console.error(`[ThreatIntel] OSV query failed for ${packageName}:`, err.message);
      return [];
    }
  }

  /**
   * Query OSV in batch (up to 1000 queries at once)
   * @param {Array<Object>} packages - Array of {name, ecosystem}
   * @returns {Promise<Array>} Normalized findings
   */
  async queryOSVBatch(packages) {
    const results = [];
    // OSV batch endpoint supports up to 1000 queries
    const batchSize = 100;
    const ecosystemMap = { npm: 'npm', pypi: 'PyPI' };

    for (let i = 0; i < packages.length; i += batchSize) {
      const batch = packages.slice(i, i + batchSize);
      const queries = batch.map(pkg => ({
        package: {
          name: pkg.name,
          ecosystem: ecosystemMap[pkg.ecosystem] || pkg.ecosystem
        }
      }));

      try {
        const response = await this.safeFetch('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries })
        });

        if (!response.ok) {
          console.error(`[ThreatIntel] OSV batch query failed: ${response.status}`);
          continue;
        }

        const data = await response.json();
        const batchResults = data.results || [];

        for (let j = 0; j < batchResults.length; j++) {
          const vulns = batchResults[j].vulns || [];
          const pkg = batch[j];
          for (const vuln of vulns) {
            results.push(this.normalizeOSV(vuln, pkg.name, pkg.ecosystem));
          }
        }
      } catch (err) {
        console.error('[ThreatIntel] OSV batch query error:', err.message);
      }

      // Rate limit courtesy
      if (i + batchSize < packages.length) {
        await new Promise(r => setTimeout(r, 1000));
      }
    }

    return results;
  }

  /**
   * Normalize an OSV vulnerability to common format
   * @param {Object} vuln - OSV vulnerability object
   * @param {string} packageName - Package name
   * @param {string} ecosystem - Ecosystem
   * @returns {Object} Normalized finding
   */
  normalizeOSV(vuln, packageName, ecosystem) {
    return {
      id: vuln.id,
      source: 'OSV',
      severity: this.parseSeverity(vuln),
      package: packageName,
      ecosystem,
      summary: vuln.summary || vuln.details?.substring(0, 200) || 'No summary available',
      publishedDate: vuln.published || null,
      url: `https://osv.dev/vulnerability/${vuln.id}`
    };
  }

  /**
   * Query GitHub Advisory Database
   * @param {string} ecosystem - 'npm' or 'pip' (GitHub uses 'pip' not 'PyPI')
   * @param {number} daysBack - How many days back to look
   * @returns {Promise<Array>} Normalized findings
   */
  async queryGitHubAdvisories(ecosystem = 'npm', daysBack = 7) {
    const ghEcosystem = ecosystem === 'pypi' ? 'pip' : ecosystem;
    const since = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000).toISOString();

    const headers = { 'Accept': 'application/vnd.github+json' };
    if (this.githubToken) {
      headers['Authorization'] = `Bearer ${this.githubToken}`;
    }

    try {
      const url = `https://api.github.com/advisories?ecosystem=${ghEcosystem}&published=${since}&per_page=100&sort=published&direction=desc`;
      const response = await this.safeFetch(url, { headers });

      if (!response.ok) {
        // Rate limited without token — expected
        if (response.status === 403 || response.status === 429) {
          console.warn('[ThreatIntel] GitHub Advisories rate limited (no token or quota exceeded)');
          return [];
        }
        console.error(`[ThreatIntel] GitHub Advisories error: ${response.status}`);
        return [];
      }

      const advisories = await response.json();
      return advisories.map(adv => this.normalizeGitHubAdvisory(adv, ecosystem));
    } catch (err) {
      console.error('[ThreatIntel] GitHub Advisories query failed:', err.message);
      return [];
    }
  }

  /**
   * Normalize a GitHub advisory to common format
   * @param {Object} adv - GitHub advisory object
   * @param {string} ecosystem - Ecosystem
   * @returns {Object} Normalized finding
   */
  normalizeGitHubAdvisory(adv, ecosystem) {
    const pkg = adv.vulnerabilities?.[0]?.package?.name || 'unknown';
    return {
      id: adv.ghsa_id || adv.cve_id || adv.html_url,
      source: 'GitHub Advisory',
      severity: (adv.severity || 'medium').toLowerCase(),
      package: pkg,
      ecosystem,
      summary: adv.summary || 'No summary available',
      publishedDate: adv.published_at || null,
      url: adv.html_url || `https://github.com/advisories/${adv.ghsa_id}`
    };
  }

  /**
   * Query NVD (National Vulnerability Database) for recent CVEs
   * @param {number} daysBack - How many days back to look
   * @returns {Promise<Array>} Normalized findings
   */
  async queryNVD(daysBack = 3) {
    const pubStartDate = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000)
      .toISOString().replace(/\.\d{3}Z$/, '.000');
    const pubEndDate = new Date().toISOString().replace(/\.\d{3}Z$/, '.000');

    try {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}&resultsPerPage=100`;
      const response = await this.safeFetch(url, {}, 30000);

      if (!response.ok) {
        console.error(`[ThreatIntel] NVD error: ${response.status}`);
        return [];
      }

      const data = await response.json();
      const cves = data.vulnerabilities || [];

      return cves
        .map(item => this.normalizeNVD(item))
        .filter(item => item !== null);
    } catch (err) {
      console.error('[ThreatIntel] NVD query failed:', err.message);
      return [];
    }
  }

  /**
   * Normalize an NVD CVE to common format
   * @param {Object} item - NVD CVE item
   * @returns {Object|null} Normalized finding or null
   */
  normalizeNVD(item) {
    const cve = item.cve;
    if (!cve) return null;

    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';

    // Try to extract package/ecosystem from description
    let pkg = 'unknown';
    let ecosystem = 'unknown';

    // Common patterns: "in <package>" or "<package> before version"
    const npmMatch = description.match(/(?:in |package )(\S+?)(?:\s|,|\.)/i);
    if (npmMatch) pkg = npmMatch[1];

    // Check if it mentions npm or node
    if (/\b(npm|node\.?js|javascript)\b/i.test(description)) {
      ecosystem = 'npm';
    } else if (/\b(pip|pypi|python)\b/i.test(description)) {
      ecosystem = 'pypi';
    }

    // Get severity from CVSS
    let severity = 'medium';
    const metrics = cve.metrics;
    if (metrics?.cvssMetricV31?.[0]) {
      const score = metrics.cvssMetricV31[0].cvssData?.baseScore || 0;
      severity = this.scoreToseverity(score);
    } else if (metrics?.cvssMetricV30?.[0]) {
      const score = metrics.cvssMetricV30[0].cvssData?.baseScore || 0;
      severity = this.scoreToseverity(score);
    }

    return {
      id: cve.id,
      source: 'NVD',
      severity,
      package: pkg,
      ecosystem,
      summary: description.substring(0, 300),
      publishedDate: cve.published || null,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
    };
  }

  /**
   * Fetch CISA Known Exploited Vulnerabilities catalog
   * @returns {Promise<Array>} Normalized findings
   */
  async queryCISA() {
    try {
      const response = await this.safeFetch(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
      );

      if (!response.ok) {
        console.error(`[ThreatIntel] CISA feed error: ${response.status}`);
        return [];
      }

      const data = await response.json();
      const vulnerabilities = data.vulnerabilities || [];

      // Only return recent entries (last 30 days)
      const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

      return vulnerabilities
        .filter(v => new Date(v.dateAdded) >= cutoff)
        .map(v => ({
          id: v.cveID,
          source: 'CISA KEV',
          severity: 'critical', // CISA KEV = actively exploited = critical
          package: v.product || 'unknown',
          ecosystem: 'unknown',
          summary: `${v.vulnerabilityName}: ${v.shortDescription}`,
          publishedDate: v.dateAdded,
          url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`
        }));
    } catch (err) {
      console.error('[ThreatIntel] CISA feed failed:', err.message);
      return [];
    }
  }

  /**
   * Fetch all threat intelligence feeds
   * Uses cache if available and fresh
   * @param {Object} options - { ecosystems: ['npm', 'pypi'], daysBack: 7 }
   * @returns {Promise<Object>} { findings: Array, metadata: Object }
   */
  async fetchAll(options = {}) {
    const { ecosystems = ['npm', 'pypi'], daysBack = 7 } = options;

    // Check cache first
    const cached = this.loadCache();
    if (cached) {
      return cached;
    }

    console.log('[ThreatIntel] Fetching from all threat intelligence sources...');
    const startTime = Date.now();
    const allFindings = [];
    const sourceStatus = {};

    // Fetch from all sources in parallel
    const [githubNpm, githubPypi, nvd, cisa] = await Promise.allSettled([
      this.queryGitHubAdvisories('npm', daysBack),
      this.queryGitHubAdvisories('pypi', daysBack),
      this.queryNVD(Math.min(daysBack, 7)), // NVD has rate limits, keep it small
      this.queryCISA()
    ]);

    // Process GitHub npm advisories
    if (githubNpm.status === 'fulfilled') {
      allFindings.push(...githubNpm.value);
      sourceStatus['GitHub Advisory (npm)'] = { count: githubNpm.value.length, status: 'ok' };
    } else {
      sourceStatus['GitHub Advisory (npm)'] = { count: 0, status: 'error', error: githubNpm.reason?.message };
    }

    // Process GitHub PyPI advisories
    if (githubPypi.status === 'fulfilled') {
      allFindings.push(...githubPypi.value);
      sourceStatus['GitHub Advisory (pypi)'] = { count: githubPypi.value.length, status: 'ok' };
    } else {
      sourceStatus['GitHub Advisory (pypi)'] = { count: 0, status: 'error', error: githubPypi.reason?.message };
    }

    // Process NVD
    if (nvd.status === 'fulfilled') {
      allFindings.push(...nvd.value);
      sourceStatus['NVD'] = { count: nvd.value.length, status: 'ok' };
    } else {
      sourceStatus['NVD'] = { count: 0, status: 'error', error: nvd.reason?.message };
    }

    // Process CISA
    if (cisa.status === 'fulfilled') {
      allFindings.push(...cisa.value);
      sourceStatus['CISA KEV'] = { count: cisa.value.length, status: 'ok' };
    } else {
      sourceStatus['CISA KEV'] = { count: 0, status: 'error', error: cisa.reason?.message };
    }

    // Deduplicate by ID
    const seen = new Set();
    const deduplicated = allFindings.filter(f => {
      if (seen.has(f.id)) return false;
      seen.add(f.id);
      return true;
    });

    const result = {
      findings: deduplicated,
      metadata: {
        totalFindings: deduplicated.length,
        sources: sourceStatus,
        ecosystems,
        daysBack,
        fetchDurationMs: Date.now() - startTime
      },
      fetchedAt: Date.now()
    };

    // Save cache
    this.saveCache(result);

    console.log(`[ThreatIntel] Fetched ${deduplicated.length} findings from ${Object.keys(sourceStatus).length} sources in ${result.metadata.fetchDurationMs}ms`);

    return result;
  }

  /**
   * Query threat feeds for specific packages (uses OSV batch)
   * @param {Array<Object>} packages - Array of {name, ecosystem}
   * @returns {Promise<Array>} Findings for those packages
   */
  async queryPackages(packages) {
    if (!packages || packages.length === 0) return [];

    console.log(`[ThreatIntel] Querying OSV for ${packages.length} packages...`);
    const findings = await this.queryOSVBatch(packages);
    console.log(`[ThreatIntel] Found ${findings.length} vulnerabilities in queried packages`);
    return findings;
  }

  /**
   * Cross-reference installed packages against cached threat intel
   * @param {Array<Object>} installedPackages - Array of {name, ecosystem}
   * @returns {Object} { matches: Array, summary: Object }
   */
  crossReference(installedPackages, findings) {
    const packageSet = new Set(installedPackages.map(p => p.name.toLowerCase()));

    const matches = findings.filter(f =>
      f.package && packageSet.has(f.package.toLowerCase())
    );

    const summary = {
      totalInstalled: installedPackages.length,
      totalFindings: findings.length,
      matchedVulnerabilities: matches.length,
      severity: {
        critical: matches.filter(m => m.severity === 'critical').length,
        high: matches.filter(m => m.severity === 'high').length,
        medium: matches.filter(m => m.severity === 'medium').length,
        low: matches.filter(m => m.severity === 'low').length
      }
    };

    return { matches, summary };
  }

  /**
   * Look up a single package in the threat intel cache
   * @param {string} packageName - Package name
   * @param {string} ecosystem - Ecosystem
   * @returns {Array} Matching findings from cache
   */
  lookupPackage(packageName, ecosystem = 'npm') {
    const cached = this.loadCache();
    if (!cached || !cached.findings) return [];

    const name = packageName.toLowerCase();
    return cached.findings.filter(f =>
      f.package?.toLowerCase() === name &&
      (f.ecosystem === ecosystem || f.ecosystem === 'unknown')
    );
  }

  /**
   * Parse severity from various vuln formats
   * @param {Object} vuln - Vulnerability object
   * @returns {string} Severity level
   */
  parseSeverity(vuln) {
    // Check database_specific severity
    if (vuln.database_specific?.severity) {
      return vuln.database_specific.severity.toLowerCase();
    }

    // Check CVSS severity array
    if (vuln.severity && vuln.severity.length > 0) {
      const cvss = vuln.severity.find(s => s.type === 'CVSS_V3');
      if (cvss && cvss.score) {
        // score might be the full vector string, parse the numeric part
        const scoreStr = typeof cvss.score === 'string'
          ? cvss.score.match(/(\d+\.?\d*)/)?.[1]
          : cvss.score;
        const score = parseFloat(scoreStr);
        if (!isNaN(score)) {
          return this.scoreToseverity(score);
        }
      }
    }

    // Fallback from summary keywords
    const summary = (vuln.summary || '').toLowerCase();
    if (summary.includes('critical') || summary.includes('remote code execution')) return 'critical';
    if (summary.includes('high') || summary.includes('exploit')) return 'high';
    return 'medium';
  }

  /**
   * Convert CVSS numeric score to severity string
   * @param {number} score - CVSS score
   * @returns {string} Severity level
   */
  scoreToseverity(score) {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }
}
