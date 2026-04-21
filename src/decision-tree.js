/**
 * Decision Tree Logic
 * Determines threat level: BARK (danger), WHINE (suspicious), or SILENT (safe)
 */

export class DecisionTree {
  constructor(config, trustedProviders) {
    this.thresholds = config.decisionThresholds;
    this.trusted = trustedProviders;
  }

  /**
   * Evaluate threat level based on scan and reputation data
   * @param {Object} scanResults - VirusTotal scan results
   * @param {Object} reputationData - Reputation check results
   * @param {string} packageName - Package name
   * @param {Object} cveResults - CVE check results
   * @param {Object} patternResults - Pattern analysis results
   * @returns {Object} Decision with action and reasoning
   */
  evaluate(scanResults, reputationData, packageName, cveResults = null, patternResults = null, vtAttempted = false) {
    const decision = {
      action: 'SILENT',
      threat: 'SAFE',
      confidence: 100,
      reasons: [],
      details: {
        scan: scanResults,
        reputation: reputationData
      }
    };

    // Check known-compromised list FIRST — overrides trusted provider status
    const compromised = (this.trusted.knownCompromised || []).find(
      entry => entry.name === packageName
    );
    if (compromised) {
      decision.action = 'BARK';
      decision.threat = 'DANGER';
      decision.confidence = 100;
      decision.reasons.push(`🚨 Known compromised package: ${compromised.reason}`);
      decision.reasons.push(`Flagged since: ${compromised.since}`);
      if (compromised.reference) {
        decision.reasons.push(`Reference: ${compromised.reference}`);
      }
      return decision;
    }

    // Check if trusted provider (skip further checks)
    if (this.isTrustedProvider(packageName)) {
      decision.reasons.push('Trusted provider - scanning skipped');
      return decision;
    }

    // Evaluate VirusTotal results
    const vtScore = this.evaluateVirusTotal(scanResults, decision.reasons, vtAttempted);
    
    // Evaluate reputation signals
    const repScore = this.evaluateReputation(reputationData, decision.reasons);

    // Evaluate CVE results
    const cveScore = this.evaluateCVEs(cveResults, decision.reasons);

    // Evaluate pattern analysis
    const patternScore = this.evaluatePatterns(patternResults, decision.reasons);

    // Calculate combined threat score
    const totalScore = vtScore + repScore + cveScore + patternScore;

    // Determine action based on score
    if (totalScore >= 100) {
      decision.action = 'BARK';
      decision.threat = 'DANGER';
      decision.confidence = Math.min(totalScore, 100);
    } else if (totalScore >= 50) {
      decision.action = 'WHINE';
      decision.threat = 'SUSPICIOUS';
      decision.confidence = totalScore;
    } else {
      decision.action = 'SILENT';
      decision.threat = 'SAFE';
      decision.confidence = 100 - totalScore;
    }

    return decision;
  }

  /**
   * Check if package is from a trusted provider
   * @param {string} packageName - Package name
   * @returns {boolean} Is trusted
   */
  isTrustedProvider(packageName) {
    // Check exact matches
    if (this.trusted.trustedProviders.includes(packageName)) {
      return true;
    }

    // Check namespaced packages
    for (const namespace of this.trusted.trustedNamespaces) {
      if (packageName.startsWith(namespace + '/')) {
        return true;
      }
    }

    // Check trusted scopes (e.g., @vercel/analytics matches scope "vercel")
    if (packageName.startsWith('@')) {
      const scope = packageName.slice(1).split('/')[0];
      const npmScopes = (this.trusted.trustedScopes?.npm || []);
      if (npmScopes.includes(scope)) {
        return true;
      }
    }

    // Check rubygems trusted packages (exact name match against rubygems scope list)
    const rubygemsTrusted = this.trusted.trustedScopes?.rubygems || [];
    if (rubygemsTrusted.includes(packageName)) {
      return true;
    }

    return false;
  }

  /**
   * Evaluate VirusTotal scan results
   * @param {Object} scanResults - Scan results
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluateVirusTotal(scanResults, reasons, vtAttempted = false) {
    let score = 0;

    if (!scanResults.success) {
      // Only penalize if VT was actually attempted (API key set + target provided)
      if (!vtAttempted) {
        return 0;
      }
      reasons.push('VirusTotal scan failed - treating as suspicious');
      return 20;
    }

    if (!scanResults.found) {
      reasons.push('No VirusTotal data available');
      return 10;
    }

    const malicious = scanResults.maliciousVotes || 0;
    const suspicious = scanResults.suspiciousVotes || 0;

    // Malicious detections
    if (malicious >= this.thresholds.maliciousVotes) {
      score += 70;
      reasons.push(`⚠️ ${malicious} engines flagged as MALICIOUS`);
    } else if (malicious > 0) {
      score += 30;
      reasons.push(`⚠️ ${malicious} engine(s) flagged as malicious`);
    }

    // Suspicious detections
    if (suspicious >= this.thresholds.suspiciousVotes) {
      score += 20;
      reasons.push(`${suspicious} engines flagged as SUSPICIOUS`);
    }

    return score;
  }

  /**
   * Evaluate reputation signals
   * @param {Object} reputationData - Reputation data
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluateReputation(reputationData, reasons) {
    let score = 0;

    if (!reputationData || reputationData.error) {
      reasons.push('Unable to verify package reputation');
      return 15;
    }

    const signals = reputationData.signals || [];

    // Critical signals (high risk)
    if (signals.includes('PACKAGE_NOT_FOUND')) {
      score += 30;
      reasons.push('❌ Package not found in registry');
    }

    if (signals.includes('SECURITY_COMPLAINTS')) {
      score += 40;
      reasons.push('🚨 Security issues reported on GitHub');
    }

    if (signals.includes('DISABLED_REPO')) {
      score += 35;
      reasons.push('❌ Repository disabled');
    }

    // Warning signals (medium risk)
    if (signals.includes('DEPRECATED')) {
      score += 15;
      reasons.push('⚠️ Package is deprecated');
    }

    if (signals.includes('NEWLY_PUBLISHED')) {
      score += 20;
      reasons.push('🆕 Recently published (< 30 days)');
    }

    if (signals.includes('NO_REPOSITORY')) {
      score += 25;
      reasons.push('❓ No source repository linked');
    }

    if (signals.includes('ARCHIVED_REPO')) {
      score += 10;
      reasons.push('📦 Repository is archived');
    }

    // Low-risk signals
    if (signals.includes('LOW_DOWNLOADS')) {
      score += 10;
      reasons.push('📉 Low weekly downloads (< 1,000)');
    }

    if (signals.includes('LOW_STARS')) {
      score += 5;
      reasons.push('⭐ Low GitHub stars (< 50)');
    }

    if (signals.includes('NO_MAINTAINERS')) {
      score += 10;
      reasons.push('👤 No active maintainers');
    }

    return Math.min(score, 100);
  }

  /**
   * Evaluate CVE results
   * @param {Object} cveResults - CVE check results
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluateCVEs(cveResults, reasons) {
    if (!cveResults || !cveResults.found) {
      return 0;
    }

    let score = 0;
    const severity = cveResults.severity;

    // Critical vulnerabilities
    if (severity.critical > 0) {
      score += severity.critical * 25;
      reasons.push(`🚨 ${severity.critical} CRITICAL CVE(s) found`);
    }

    // High severity
    if (severity.high > 0) {
      score += severity.high * 15;
      reasons.push(`⚠️ ${severity.high} HIGH severity CVE(s) found`);
    }

    // Medium severity
    if (severity.medium > 0) {
      score += severity.medium * 5;
      reasons.push(`⚠️ ${severity.medium} MEDIUM severity CVE(s) found`);
    }

    // Low severity
    if (severity.low > 0) {
      score += severity.low * 2;
      reasons.push(`ℹ️ ${severity.low} LOW severity CVE(s) found`);
    }

    return Math.min(score, 100);
  }

  /**
   * Evaluate pattern analysis results
   * @param {Object} patternResults - Pattern analysis results
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluatePatterns(patternResults, reasons) {
    if (!patternResults || !patternResults.suspicious) {
      return 0;
    }

    const score = patternResults.score || 0;
    const severity = patternResults.severity || patternResults.combinedSeverity;

    if (!severity) return 0;

    // Add specific pattern warnings
    if (severity.critical > 0) {
      reasons.push(`🔴 ${severity.critical} CRITICAL pattern(s) detected in code`);
    }

    if (severity.high > 0) {
      reasons.push(`⚠️ ${severity.high} HIGH-risk pattern(s) detected`);
    }

    if (severity.medium > 0) {
      reasons.push(`⚠️ ${severity.medium} MEDIUM-risk pattern(s) detected`);
    }

    if (severity.low > 0 && severity.low > 5) {
      reasons.push(`ℹ️ ${severity.low} LOW-risk pattern(s) detected`);
    }

    return Math.min(score, 100);
  }

  /**
   * Format decision for display
   * @param {Object} decision - Decision object
   * @returns {string} Formatted output
   */
  formatDecision(decision) {
    const emoji = {
      BARK: '🚨',
      WHINE: '⚠️',
      SILENT: '✅'
    };

    let output = `${emoji[decision.action]} ${decision.action}: ${decision.threat}\n`;
    output += `Confidence: ${decision.confidence}%\n\n`;

    if (decision.reasons.length > 0) {
      output += 'Reasons:\n';
      decision.reasons.forEach(reason => {
        output += `  • ${reason}\n`;
      });
    }

    return output;
  }
}
