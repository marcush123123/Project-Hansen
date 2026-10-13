import { promises as fs, createReadStream } from 'fs';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import { ExtractionService, LIMITS } from '../services/ExtractionService';
import { ManifestParser } from '../services/ManifestParser';
import { StaticAnalyzer } from '../services/StaticAnalyzer';
import { assess } from '../services/Assessment';
import { AnalysisProgress, AnalysisReport, PackageSummary } from '../types';
import { localMalwareFindings, updateMalwareAssessment } from '../services/MalwareAssessment';
import { SignatureService } from '../services/SignatureService';
export async function analyzeApkWorkflow(input: string, tempDir: string, onProgress: (p: AnalysisProgress) => void): Promise<AnalysisReport> {
  const started = Date.now();
  const step = (name: string) => onProgress({ step: name, status: 'running' });
  try {
    step('Validating and extracting package');
    const original = await fs.stat(input);
    if (!original.isFile() || original.size > LIMITS.archiveBytes || !/\.(apk|xapk)$/i.test(input)) throw new Error('Choose an APK or XAPK file no larger than 2 GiB');
    // Analyze and hash the same snapshot even if the source file changes during inspection.
    await fs.mkdir(tempDir, { recursive: true });
    const snapshot = path.join(tempDir, `input${path.extname(input).toLowerCase()}`);
    await fs.copyFile(input, snapshot);
    const fileSize = (await fs.stat(snapshot)).size;
    const extracted = await ExtractionService.extract(snapshot, tempDir);
    if (/\.apk$/i.test(input)) extracted.packages[0].fileName = path.basename(input);
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(snapshot)) hash.update(chunk);
    const sha256 = hash.digest('hex');
    step('Decoding Android manifests');
    const packages: PackageSummary[] = [];
    for (const p of extracted.packages) packages.push({ fileName: p.fileName, sha256: p.sha256 || sha256, manifest: await ManifestParser.parseManifest(p.dir), signature: await SignatureService.inspect(p.sourcePath), entries: p.entries, dexFiles: p.dexFiles, nativeLibraries: p.nativeLibraries });
    const bases = packages.filter(p => !p.manifest.split);
    if (bases.length !== 1) throw new Error('Expected exactly one base APK; the container is incomplete or ambiguous');
    const base = bases[0].manifest;
    // Split manifests inherit omitted SDK and application defaults from their base.
    for (let i = 0; i < packages.length; i++) if (packages[i].manifest.split) packages[i].manifest = await ManifestParser.parseManifest(extracted.packages[i].dir, base);
    if (packages.some(p => p.manifest.packageName !== base.packageName || p.manifest.versionCode !== base.versionCode)) throw new Error('XAPK contains mismatched package names or version codes');
    if (new Set(packages.map(p => p.manifest.split)).size !== packages.length) throw new Error('XAPK contains duplicate split identifiers');
    step('Scanning DEX, native libraries and resources');
    const scans = [];
    for (const p of extracted.packages) scans.push(await StaticAnalyzer.analyzeCode(p.dir));
    const unique = (items: string[]) => [...new Set(items)].sort();
    const origins = unique(scans.flatMap(s => s.endpoints));
    const report: AnalysisReport = {
      id: randomUUID(), createdAt: new Date().toISOString(), fileName: path.basename(input), fileSize, sha256, format: /\.xapk$/i.test(input) ? 'XAPK' : 'APK', durationMs: 0,
      packages, context: { packageName: base.packageName, versionCode: base.versionCode, versionName: base.versionName,
        permissions: unique(packages.flatMap(p => p.manifest.permissions)), exportedActivities: unique(packages.flatMap(p => p.manifest.components.filter(c => c.exported && c.type.startsWith('activity')).map(c => c.name))),
        exportedServices: unique(packages.flatMap(p => p.manifest.components.filter(c => c.exported && c.type === 'service').map(c => c.name))),
        endpoints: origins.slice(0, 250), apiKeys: unique(scans.flatMap(s => s.apiKeys)), trackerSDKs: unique(scans.flatMap(s => s.trackerSDKs)), suspiciousPatterns: unique(scans.flatMap(s => s.suspiciousPatterns)) },
      findings: [], assessment: {} as AnalysisReport['assessment'], warnings: [...extracted.warnings,
        'Static analysis only: APK code was not executed. Signing certificate identity may be extracted, but cryptographic signature validity, runtime behavior and server-side controls are not verified. See the separate VirusTotal section for reputation coverage.',
        'Media, OBB and unrecognized file types are excluded. Obfuscation, encryption, downloaded code and unknown SDKs can hide behavior.',
        'Network strings are reduced to origins; URL paths, credentials, query strings and fragments are omitted. Credential values are never retained.',
        'Resource references such as @0x... are unresolved. Network security and backup XML rules are not interpreted. Permission SDK restrictions are not modeled.'
      ], coverage: { scannedFiles: scans.reduce((n,s) => n+s.scannedFiles,0), scannedBytes: scans.reduce((n,s) => n+s.scannedBytes,0), skippedFiles: extracted.packages.reduce((n,p) => n+p.skippedFiles,0), endpointLimit: 250 },
    };
    if (origins.length > 250 || scans.some(s => s.endpointsTruncated)) report.warnings.push('Network origin inventory reached the 250-origin limit; additional matches are omitted.');
    const evidence: Record<string, string[]> = {};
    scans.forEach((s,i) => Object.entries(s.evidence).forEach(([k,v]) => { evidence[k] = [...(evidence[k] || []), ...v.map(f => `${packages[i].fileName}/${f}`)]; }));
    Object.assign(report, assess(report, evidence));
    report.reputation = packages.map(p => ({ sha256: p.sha256!, fileName: p.fileName, status: 'not-checked', message: 'VirusTotal has not been checked for this APK.' }));
    updateMalwareAssessment(report, localMalwareFindings(report, evidence));
    report.durationMs = Date.now() - started;
    onProgress({ step: 'Report ready', status: 'completed' });
    return report;
  } finally { await ExtractionService.cleanup(tempDir); }
}
