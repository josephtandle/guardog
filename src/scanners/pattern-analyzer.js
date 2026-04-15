/**
 * Suspicious Pattern Analyzer
 * Detects malicious code patterns in package code
 */

export class PatternAnalyzer {
  constructor(config) {
    this.config = config?.patterns || {};
    this.suspiciousPatterns = [
      // Command execution
      { pattern: /eval\s*\(/gi, severity: 'high', name: 'eval() usage' },
      { pattern: /exec\s*\(/gi, severity: 'high', name: 'exec() usage' },
      { pattern: /execFile\s*\(/gi, severity: 'medium', name: 'execFile() usage' },
      { pattern: /spawn\s*\(/gi, severity: 'medium', name: 'spawn() usage' },
      { pattern: /child_process/gi, severity: 'medium', name: 'child_process module' },
      
      // Network requests to suspicious domains
      { pattern: /https?:\/\/[^'")\s]*\.ru['")\s]/gi, severity: 'medium', name: 'Request to .ru domain' },
      { pattern: /https?:\/\/[^'")\s]*\.cn['")\s]/gi, severity: 'low', name: 'Request to .cn domain' },
      { pattern: /pastebin\.com/gi, severity: 'medium', name: 'Pastebin reference' },
      
      // Obfuscation
      { pattern: /atob\s*\(/gi, severity: 'high', name: 'Base64 decode (atob)' },
      { pattern: /btoa\s*\(/gi, severity: 'medium', name: 'Base64 encode (btoa)' },
      { pattern: /\\x[0-9a-f]{2}/gi, severity: 'medium', name: 'Hex-encoded strings' },
      { pattern: /String\.fromCharCode/gi, severity: 'high', name: 'Character code obfuscation' },
      
      // File system access
      { pattern: /unlinkSync\s*\(/gi, severity: 'medium', name: 'File deletion (unlinkSync)' },
      { pattern: /rmdirSync\s*\(/gi, severity: 'medium', name: 'Directory deletion' },
      { pattern: /writeFileSync\s*\(/gi, severity: 'low', name: 'File writing' },
      
      // Credential access
      { pattern: /\.npmrc/gi, severity: 'high', name: 'npm credentials access' },
      { pattern: /\.ssh/gi, severity: 'high', name: 'SSH credentials access' },
      { pattern: /\.aws\/credentials/gi, severity: 'high', name: 'AWS credentials access' },
      { pattern: /process\.env/gi, severity: 'low', name: 'Environment variable access' },
      
      // Crypto mining
      { pattern: /coinhive/gi, severity: 'critical', name: 'Coinhive crypto miner' },
      { pattern: /crypto-loot/gi, severity: 'critical', name: 'CryptoLoot miner' },
      { pattern: /minero\.cc/gi, severity: 'critical', name: 'Minero crypto miner' },
      
      // Suspicious Python patterns
      { pattern: /__import__\s*\(/gi, severity: 'high', name: 'Dynamic import (__import__)' },
      { pattern: /compile\s*\(/gi, severity: 'medium', name: 'Code compilation' },
      { pattern: /os\.system/gi, severity: 'high', name: 'System command execution' },
      { pattern: /subprocess\./gi, severity: 'medium', name: 'Subprocess module' },
      
      // Reverse shells
      { pattern: /socket\.connect/gi, severity: 'high', name: 'Socket connection' },
      { pattern: /\/bin\/bash/gi, severity: 'medium', name: 'Bash shell reference' },
      { pattern: /\/bin\/sh/gi, severity: 'medium', name: 'Shell reference' },
      
      // Data exfiltration
      { pattern: /XMLHttpRequest/gi, severity: 'low', name: 'XMLHttpRequest' },
      { pattern: /fetch\s*\(/gi, severity: 'low', name: 'Fetch API' },
      { pattern: /navigator\./gi, severity: 'low', name: 'Navigator object access' }
    ];
  }

  /**
   * Analyze code for suspicious patterns
   * @param {string} code - Source code to analyze
   * @param {string} filename - Optional filename for context
   * @returns {Object} Analysis results
   */
  analyzeCode(code, filename = 'unknown') {
    const results = {
      filename,
      suspicious: false,
      matches: [],
      severity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      score: 0
    };

    if (!code || typeof code !== 'string') {
      return results;
    }

    // Check each pattern
    for (const patternDef of this.suspiciousPatterns) {
      const matches = code.match(patternDef.pattern);
      if (matches) {
        results.suspicious = true;
        results.severity[patternDef.severity]++;
        
        results.matches.push({
          pattern: patternDef.name,
          severity: patternDef.severity,
          count: matches.length,
          samples: matches.slice(0, 3) // First 3 matches
        });
      }
    }

    // Calculate threat score
    results.score = this.calculateScore(results.severity);

    return results;
  }

  /**
   * Analyze multiple files
   * @param {Object} files - Map of filename -> code
   * @returns {Object} Combined analysis
   */
  analyzeFiles(files) {
    const results = {
      totalFiles: 0,
      suspiciousFiles: 0,
      allMatches: [],
      combinedSeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      totalScore: 0
    };

    for (const [filename, code] of Object.entries(files)) {
      results.totalFiles++;
      const fileResult = this.analyzeCode(code, filename);
      
      if (fileResult.suspicious) {
        results.suspiciousFiles++;
        results.allMatches.push(fileResult);
        
        // Aggregate severity counts
        for (const severity in fileResult.severity) {
          results.combinedSeverity[severity] += fileResult.severity[severity];
        }
      }
    }

    results.totalScore = this.calculateScore(results.combinedSeverity);

    return results;
  }

  /**
   * Calculate threat score from severity counts
   * @param {Object} severity - Severity counts
   * @returns {number} Score (0-100)
   */
  calculateScore(severity) {
    let score = 0;
    
    score += (severity.critical || 0) * 30;
    score += (severity.high || 0) * 20;
    score += (severity.medium || 0) * 10;
    score += (severity.low || 0) * 3;

    return Math.min(score, 100);
  }

  /**
   * Format analysis results for display
   * @param {Object} results - Analysis results
   * @returns {string} Formatted output
   */
  formatResults(results) {
    if (!results.suspicious && results.suspiciousFiles === undefined) {
      return '✅ No suspicious patterns detected';
    }

    let output = '';

    if (results.suspiciousFiles !== undefined) {
      // Multi-file results
      output += `📊 Analyzed ${results.totalFiles} files\n`;
      output += `⚠️  ${results.suspiciousFiles} files with suspicious patterns\n`;
      output += `🎯 Threat Score: ${results.totalScore}/100\n\n`;
      
      if (results.allMatches.length > 0) {
        output += 'Suspicious Files:\n';
        results.allMatches.forEach(match => {
          output += `  📄 ${match.filename} (score: ${match.score})\n`;
          match.matches.forEach(m => {
            output += `     • ${m.pattern} (${m.severity}, ${m.count}x)\n`;
          });
        });
      }
    } else {
      // Single file results
      output += `📄 ${results.filename}\n`;
      output += `🎯 Threat Score: ${results.score}/100\n\n`;
      
      if (results.matches.length > 0) {
        output += 'Detected Patterns:\n';
        results.matches.forEach(m => {
          output += `  • ${m.pattern} (${m.severity}, ${m.count}x)\n`;
          if (m.samples.length > 0) {
            m.samples.forEach(sample => {
              const preview = sample.substring(0, 50);
              output += `    - ${preview}${sample.length > 50 ? '...' : ''}\n`;
            });
          }
        });
      }
    }

    return output;
  }
}
