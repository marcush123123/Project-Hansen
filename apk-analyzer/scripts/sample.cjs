const { buildSync } = require('esbuild');
const { mkdtemp, writeFile, mkdir } = require('fs/promises');
const { resolve, join } = require('path');
const os = require('os');
(async () => {
  await mkdir('output', { recursive: true });
  buildSync({ entryPoints: ['src/main/apkAnalyzer.ts'], bundle: true, platform: 'node', format: 'cjs', outfile: 'output/analyzer.cjs' });
  buildSync({ entryPoints: ['src/services/ReportGenerator.ts'], bundle: true, platform: 'node', format: 'cjs', outfile: 'output/report-generator.cjs' });
  const { analyzeApkWorkflow } = require('../output/analyzer.cjs');
  const { ReportGenerator } = require('../output/report-generator.cjs');
  const input = resolve(process.argv[2] || '../TikTok+-+Videos,+Shop+&+LIVE_47.1.4_APKPure.apk');
  const report = await analyzeApkWorkflow(input, await mkdtemp(join(os.tmpdir(), 'hansen-sample-')), p => console.log(p.step));
  await writeFile('output/sample-report.json', JSON.stringify(report, null, 2));
  await writeFile('output/sample-report.html', ReportGenerator.buildHtmlReport(report));
  console.log(JSON.stringify({ package: report.context.packageName, version: report.context.versionName, permissions: report.context.permissions.length, components: report.packages.reduce((n,p) => n+p.manifest.components.length,0), trackers: report.context.trackerSDKs, findings: report.findings.length, coverage: report.coverage, durationMs: report.durationMs, sha256: report.sha256 }, null, 2));
})().catch(e => { console.error(e); process.exitCode = 1; });
