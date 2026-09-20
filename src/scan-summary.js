export function summarizeDependencyScan(inventory, results) {
  const dangerousCount = results.filter(result => result.decision?.action === 'BARK').length;
  const issues = [...inventory.issues];
  let incompleteCount = 0;
  results.forEach((result, index) => {
    const failures = [];
    if (result.decision?.coverage !== 'complete') failures.push(`scan coverage ${result.decision?.coverage || 'not reported'}`);
    if (result.cveResults?.status !== 'complete') failures.push(`CVE check ${result.cveResults?.status || 'not reported'}${result.cveResults?.error ? ': ' + result.cveResults.error : ''}`);
    if (result.scanResults?.error) failures.push(`VirusTotal: ${result.scanResults.error}`);
    for (const [name, check] of Object.entries(result.checks || result.decision?.checks || {})) {
      const status = typeof check === 'string' ? check : check?.status;
      if (status && !['complete', 'ok', 'available'].includes(status)) failures.push(`${name}: ${status}${check?.error ? ': ' + check.error : ''}`);
    }
    if (failures.length === 0) return;
    incompleteCount++;
    const pkg = inventory.packages[index];
    const name = result.packageName || pkg?.name || 'unknown package';
    const version = result.version || result.resolvedVersion || pkg?.version || 'unknown version';
    issues.push(`${name}@${version}: ${failures.join('; ')}`);
  });
  if (results.length !== inventory.packages.length) {
    const missing = Math.max(0, inventory.packages.length - results.length);
    incompleteCount += missing;
    issues.push(`Expected ${inventory.packages.length} dependency results, received ${results.length}.`);
  }
  if (!inventory.complete && inventory.issues.length === 0) issues.push('Dependency inventory coverage is incomplete.');
  const incomplete = !inventory.complete || incompleteCount > 0 || issues.length > 0;
  const quotaExhausted = results.some(result => result.scanResults?.status === 'rate_limited');
  return {
    status: dangerousCount ? 'dangerous' : incomplete ? 'incomplete' : 'complete',
    coverage: incomplete ? 'incomplete' : 'complete',
    dependencyCount: inventory.packages.length,
    dangerousCount,
    incompleteCount,
    quotaExhausted,
    issues
  };
}
