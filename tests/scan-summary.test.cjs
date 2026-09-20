const { test } = require('node:test');
const assert = require('node:assert/strict');

test('danger preserves incomplete coverage and package failure diagnostics', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const inventory = {complete:true,issues:[],packages:[{name:'bad',version:'1.0.0'},{name:'unknown',version:'2.0.0'}]};
  const report = summarizeDependencyScan(inventory,[
    {packageName:'bad',version:'1.0.0',decision:{action:'BARK',coverage:'complete'},cveResults:{status:'complete'}},
    {packageName:'unknown',version:'2.0.0',decision:{action:'SILENT',coverage:'incomplete'},cveResults:{status:'unavailable',error:'OSV timeout'}}
  ]);
  assert.equal(report.status,'dangerous');
  assert.equal(report.coverage,'incomplete');
  assert.equal(report.incompleteCount,1);
  assert.equal(report.dangerousCount,1);
  assert.equal(report.dependencyCount,2);
  assert.ok(report.issues.some(issue=>issue.includes('unknown@2.0.0') && issue.includes('OSV timeout')));
});

test('missing coverage and missing result rows cannot count as complete', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const inventory = {complete:true,issues:[],packages:[{name:'one',version:'1.0.0'},{name:'two',version:'2.0.0'}]};
  const report = summarizeDependencyScan(inventory,[{packageName:'one',decision:{action:'SILENT'},cveResults:{status:'complete'}}]);
  assert.equal(report.status,'incomplete');
  assert.equal(report.coverage,'incomplete');
  assert.equal(report.incompleteCount,2);
  assert.ok(report.issues.some(issue=>issue.includes('one@1.0.0') && issue.includes('not reported')));
  assert.ok(report.issues.some(issue=>issue.includes('received 1')));
});

test('completed dangerous evidence remains complete while inventory issues persist separately', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const inventory = {complete:true,issues:[],packages:[{name:'one',version:'1.0.0'}]};
  const results = [{decision:{action:'BARK',coverage:'complete'},cveResults:{status:'complete'}}];
  assert.deepEqual(summarizeDependencyScan(inventory,results),{status:'dangerous',coverage:'complete',dependencyCount:1,dangerousCount:1,incompleteCount:0,quotaExhausted:false,issues:[]});
  const incomplete = summarizeDependencyScan({...inventory,complete:false,issues:['unresolved local dependency']},results);
  assert.equal(incomplete.coverage,'incomplete');
  assert.equal(incomplete.status,'dangerous');
  assert.deepEqual(incomplete.issues,['unresolved local dependency']);
});

test('failed check reasons appear in issues consumed by nightly receipts', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const report = summarizeDependencyScan({complete:true,issues:[],packages:[{name:'one',version:'1.0.0'}]},[
    {decision:{action:'BARK',coverage:'incomplete'},cveResults:{status:'complete'},checks:{registry:{status:'unavailable',error:'lookup timed out'}},scanResults:{error:'VirusTotal quota exceeded'}}
  ]);
  assert.equal(report.status,'dangerous');
  assert.equal(report.incompleteCount,1);
  assert.ok(report.issues[0].includes('registry: unavailable: lookup timed out'));
  assert.ok(report.issues[0].includes('VirusTotal quota exceeded'));
});
