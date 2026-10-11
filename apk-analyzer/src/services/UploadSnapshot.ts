import { createReadStream, promises as fs } from 'fs';
import { createHash } from 'crypto';
import path from 'path';
import AdmZip from 'adm-zip';
import { AnalysisReport, ReputationResult } from '../types';
import { ExtractionService, LIMITS } from './ExtractionService';
import { VT_UPLOAD_LIMIT } from './VirusTotalService';

export async function hashFile(file: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

// Stage an immutable-to-the-user copy; only upload bytes verified against the report.
export async function prepareUpload(input: string, report: AnalysisReport, target: ReputationResult, dir: string): Promise<{ file: string; bytes: number }> {
  if (!report.packages.some(p => p.sha256 === target.sha256 && p.fileName === target.fileName)) throw new Error('APK is not part of this report. Analyze it again.');
  const stat = await fs.stat(input);
  if (!stat.isFile() || stat.size > LIMITS.archiveBytes) throw new Error('Invalid source package');
  const snapshot = path.join(dir, 'source');
  await fs.copyFile(input, snapshot);
  if (await hashFile(snapshot) !== report.sha256) throw new Error('Selected file does not match the original report SHA-256. Analyze the changed file first.');
  let file = snapshot;
  if (report.format === 'XAPK') {
    const zip = new AdmZip(snapshot);
    const { entries } = ExtractionService.validateEntries(zip, LIMITS.archiveBytes);
    const entry = entries.find(e => e.entryName === target.fileName && !e.isDirectory);
    if (!entry || entry.header.size > VT_UPLOAD_LIMIT) throw new Error('Contained APK is missing or exceeds the VirusTotal upload limit');
    file = path.join(dir, 'selected.apk');
    await fs.writeFile(file, entry.getData(), { mode: 0o600 });
  }
  const bytes = (await fs.stat(file)).size;
  if (!bytes || bytes > VT_UPLOAD_LIMIT) throw new Error('VirusTotal uploads must be no larger than 650 MiB');
  if (await hashFile(file) !== target.sha256) throw new Error('APK content does not match the selected report target');
  return { file, bytes };
}
