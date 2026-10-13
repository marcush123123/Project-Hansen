import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { analyzeApkWorkflow } from './main/apkAnalyzer';
import { SarifGenerator } from './services/SarifGenerator';

async function main() {
  const args = process.argv.slice(2), formatIndex = args.indexOf('--format'), outputIndex = args.indexOf('--output');
  const format = formatIndex >= 0 ? args[formatIndex + 1] : 'json';
  const output = outputIndex >= 0 ? args[outputIndex + 1] : '';
  const input = args.find((value, index) => !value.startsWith('-') && index !== formatIndex + 1 && index !== outputIndex + 1);
  if (!input || !['json','sarif'].includes(format)) throw new Error('Usage: hansen-analyze <package.apk|package.xapk> [--format json|sarif] [--output file]');
  const resolved = path.resolve(input), tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hansen-cli-'));
  const report = await analyzeApkWorkflow(resolved, tempDir, progress => process.stderr.write(`[Hansen] ${progress.step}\n`));
  const value = format === 'sarif' ? SarifGenerator.build(report) : report, serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (output) await fs.writeFile(path.resolve(output), serialized, { mode: 0o600 });
  else process.stdout.write(serialized);
}
main().catch(error => { process.stderr.write(`Hansen analysis failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
