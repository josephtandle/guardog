/** CVSS 3.0/3.1 base score. Unknown or incomplete vectors return null. */
export function cvssBaseScore(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const metrics = Object.fromEntries(vector.split('/').slice(1).map(part => part.split(':')));
  const scopeChanged = metrics.S === 'C';
  if (!['C', 'U'].includes(metrics.S)) return null;
  const av = { N: .85, A: .62, L: .55, P: .2 }[metrics.AV];
  const ac = { L: .77, H: .44 }[metrics.AC];
  const pr = (scopeChanged ? { N: .85, L: .68, H: .5 } : { N: .85, L: .62, H: .27 })[metrics.PR];
  const ui = { N: .85, R: .62 }[metrics.UI];
  const cia = ['C', 'I', 'A'].map(key => ({ H: .56, L: .22, N: 0 })[metrics[key]]);
  if (![av, ac, pr, ui, ...cia].every(Number.isFinite)) return null;
  const iss = 1 - cia.reduce((product, value) => product * (1 - value), 1);
  const impact = scopeChanged ? 7.52 * (iss - .029) - 3.25 * Math.pow(iss - .02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const score = Math.min(10, (scopeChanged ? 1.08 : 1) * (impact + exploitability));
  return Math.ceil(Math.round(score * 100000) / 10000) / 10;
}
