/**
 * Reputation Research Module
 * Queries npm/PyPI/GitHub for package metadata and reputation signals
 */

import fetch from 'node-fetch';

export class ReputationChecker {
  constructor(config) {
    this.config = config.reputation;
  }

  /**
   * Check package reputation across multiple sources
   * @param {string} packageName - Name of the package
   * @param {string} ecosystem - 'npm' or 'pypi'
   * @returns {Promise<Object>} Reputation data
   */
  async checkReputation(packageName, ecosystem = 'npm') {
    const results = {
      package: packageName,
      ecosystem,
      registry: null,
      github: null,
      signals: []
    };

    try {
      // Check package registry
      if (ecosystem === 'npm') {
        results.registry = await this.checkNpmRegistry(packageName);
      } else if (ecosystem === 'pypi') {
        results.registry = await this.checkPyPiRegistry(packageName);
      }

      // Check GitHub if repository URL is available
      if (results.registry?.repository) {
        results.github = await this.checkGitHub(results.registry.repository);
      }

      // Analyze signals
      results.signals = this.analyzeSignals(results);
    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  /**
   * Check npm registry
   * @param {string} packageName - Package name
   * @returns {Promise<Object>} npm metadata
   */
  async checkNpmRegistry(packageName) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.npm.timeoutMs);

    try {
      const response = await fetch(
        `${this.config.npm.registryUrl}/${encodeURIComponent(packageName)}`,
        { signal: controller.signal }
      );

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      const latestVersion = data['dist-tags']?.latest;
      const versionData = data.versions?.[latestVersion];

      // Fetch weekly downloads from npm downloads API
      let weeklyDownloads = null;
      try {
        const dlController = new AbortController();
        const dlTimeoutId = setTimeout(() => dlController.abort(), this.config.npm.timeoutMs);
        const dlResponse = await fetch(
          `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
          { signal: dlController.signal }
        );
        clearTimeout(dlTimeoutId);
        if (dlResponse.ok) {
          const dlData = await dlResponse.json();
          weeklyDownloads = dlData.downloads || null;
        }
      } catch {
        // Non-critical — leave as null
      }

      return {
        name: data.name,
        version: latestVersion,
        description: data.description,
        downloads: data.downloads?.total,
        weeklyDownloads,
        publishDate: versionData?.time || data.time?.[latestVersion],
        author: data.author?.name || versionData?.author?.name,
        maintainers: data.maintainers?.length || 0,
        repository: this.parseRepository(versionData?.repository || data.repository),
        license: versionData?.license || data.license,
        deprecated: data.deprecated || versionData?.deprecated
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Check PyPI registry
   * @param {string} packageName - Package name
   * @returns {Promise<Object>} PyPI metadata
   */
  async checkPyPiRegistry(packageName) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.pypi.timeoutMs);

    try {
      const response = await fetch(
        `${this.config.pypi.apiUrl}/${encodeURIComponent(packageName)}/json`,
        { signal: controller.signal }
      );

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      const info = data.info;

      return {
        name: info.name,
        version: info.version,
        description: info.summary,
        downloads: null, // PyPI doesn't provide this in main API
        publishDate: data.releases?.[info.version]?.[0]?.upload_time,
        author: info.author,
        repository: this.parseRepository(info.project_urls),
        license: info.license,
        deprecated: false
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Check GitHub repository
   * @param {string} repoUrl - GitHub repository URL
   * @returns {Promise<Object>} GitHub metadata
   */
  async checkGitHub(repoUrl) {
    if (!repoUrl) return null;

    // Parse owner/repo from URL
    const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) return null;

    const [, owner, repo] = match;
    const repoName = repo.replace(/\.git$/, '');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.github.timeoutMs);

    try {
      // Use GITHUB_TOKEN if available for higher rate limits (5000/hr vs 60/hr)
      const headers = {};
      const ghToken = process.env.GITHUB_TOKEN;
      if (ghToken) {
        headers['Authorization'] = `token ${ghToken}`;
      }

      const response = await fetch(
        `${this.config.github.apiUrl}/repos/${owner}/${repoName}`,
        { signal: controller.signal, headers }
      );

      if (!response.ok) {
        return null;
      }

      const data = await response.json();

      // Check for issues mentioning "malware", "virus", "security"
      const issuesResponse = await fetch(
        `${this.config.github.apiUrl}/search/issues?q=repo:${owner}/${repoName}+malware+OR+virus+OR+security+OR+compromised`,
        { signal: controller.signal, headers }
      );

      const issuesData = issuesResponse.ok ? await issuesResponse.json() : { total_count: 0 };

      return {
        stars: data.stargazers_count,
        forks: data.forks_count,
        openIssues: data.open_issues_count,
        watchers: data.watchers_count,
        createdAt: data.created_at,
        updatedAt: data.updated_at,
        securityIssues: issuesData.total_count,
        archived: data.archived,
        disabled: data.disabled
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Parse repository URL from various formats
   * @param {string|Object} repo - Repository data
   * @returns {string|null} Repository URL
   */
  parseRepository(repo) {
    if (!repo) return null;
    
    if (typeof repo === 'string') {
      return repo;
    }
    
    if (repo.url) {
      return repo.url.replace(/^git\+/, '').replace(/\.git$/, '');
    }
    
    // PyPI project_urls
    if (repo.Source) return repo.Source;
    if (repo.Repository) return repo.Repository;
    if (repo.Homepage) return repo.Homepage;
    
    return null;
  }

  /**
   * Analyze reputation signals
   * @param {Object} results - Combined results
   * @returns {Array<string>} Signal flags
   */
  analyzeSignals(results) {
    const signals = [];
    const registry = results.registry;
    const github = results.github;

    if (!registry) {
      signals.push('PACKAGE_NOT_FOUND');
      return signals;
    }

    // Check deprecation
    if (registry.deprecated) {
      signals.push('DEPRECATED');
    }

    // Check recent publication (typosquatting risk)
    if (registry.publishDate) {
      const daysSincePublish = (Date.now() - new Date(registry.publishDate)) / (1000 * 60 * 60 * 24);
      if (daysSincePublish < 30) {
        signals.push('NEWLY_PUBLISHED');
      }
    }

    // Check no repository
    if (!registry.repository) {
      signals.push('NO_REPOSITORY');
    }

    // GitHub signals
    if (github) {
      if (github.stars < 50) {
        signals.push('LOW_STARS');
      }
      if (github.securityIssues > 0) {
        signals.push('SECURITY_COMPLAINTS');
      }
      if (github.archived) {
        signals.push('ARCHIVED_REPO');
      }
      if (github.disabled) {
        signals.push('DISABLED_REPO');
      }
    }

    // Check low downloads (npm only)
    if (registry.weeklyDownloads !== null && registry.weeklyDownloads < 1000) {
      signals.push('LOW_DOWNLOADS');
    }

    // Check author/maintainer
    if (registry.maintainers === 0) {
      signals.push('NO_MAINTAINERS');
    }

    return signals;
  }
}
