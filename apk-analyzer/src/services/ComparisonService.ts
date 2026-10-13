import { AnalysisReport, ChangeSet, ReportComparison, ReportSummary } from '../types';

const change = (before: string[], after: string[]): ChangeSet => {
  const a = new Set(before), b = new Set(after);
  return { added: [...b].filter(x => !a.has(x)).sort(), removed: [...a].filter(x => !b.has(x)).sort() };
};
const fingerprints = (r: AnalysisReport) => [...new Set(r.packages.flatMap(p => p.signature?.certificates.map(c => c.sha256) || []))].sort();
const components = (r: AnalysisReport) => r.packages.flatMap(p => p.manifest.components.filter(c => c.exported).map(c => {
  const guards = [c.permission, c.readPermission, c.writePermission].filter(Boolean).join(', ');
  const routes = [...(c.deepLinks || []), ...(c.intentActions || [])].join(', ');
  return `${c.type}: ${c.name}${guards ? ` [${guards}]` : ' [unprotected]'}${routes ? ` → ${routes}` : ''}`;
}));
const findingNames = (r: AnalysisReport) => r.findings.map(f => `${f.severity}: ${f.id} — ${f.title}`);
const packageNames = (r: AnalysisReport) => r.packages.map(p => `${p.manifest.split || 'base'}: ${p.fileName}`);
const summary = (r: AnalysisReport): ReportSummary & { versionCode: string; versionName: string; sha256: string } => ({
  id: r.id, packageName: r.context.packageName, fileName: r.fileName, createdAt: r.createdAt, grade: r.assessment.grade,
  versionCode: r.context.versionCode, versionName: r.context.versionName, sha256: r.sha256,
  signerFingerprint: fingerprints(r)[0], malwareTitle: r.malware?.title, malwareVerdict: r.malware?.verdict,
});

export class ComparisonService {
  static compare(base: AnalysisReport, target: AnalysisReport): ReportComparison {
    if (base.id === target.id) throw new Error('Choose two different reports to compare');
    const baseSigners = fingerprints(base), targetSigners = fingerprints(target);
    const signer = !baseSigners.length || !targetSigners.length
      ? { status: 'unknown' as const, detail: 'A stable signing certificate identity is unavailable for one or both reports.', baseFingerprints: baseSigners, targetFingerprints: targetSigners }
      : baseSigners.some(x => targetSigners.includes(x))
        ? { status: 'same' as const, detail: 'At least one signing certificate fingerprint is shared by both releases.', baseFingerprints: baseSigners, targetFingerprints: targetSigners }
        : { status: 'changed' as const, detail: 'No signing certificate fingerprint is shared. Treat this as a publisher identity change until independently explained.', baseFingerprints: baseSigners, targetFingerprints: targetSigners };
    const result = {
      permissions: change(base.context.permissions, target.context.permissions), trackers: change(base.context.trackerSDKs, target.context.trackerSDKs),
      endpoints: change(base.context.endpoints, target.context.endpoints), capabilities: change(base.context.suspiciousPatterns, target.context.suspiciousPatterns),
      exportedComponents: change(components(base), components(target)), findings: change(findingNames(base), findingNames(target)), packages: change(packageNames(base), packageNames(target)),
    };
    const materialChangeCount = Object.values(result).reduce((n, c) => n + c.added.length + c.removed.length, 0) + (signer.status === 'changed' ? 1 : 0);
    const samePackage = base.context.packageName === target.context.packageName;
    const headline = !samePackage ? 'These reports have different Android package identities.' : signer.status === 'changed' ? 'Signing identity changed between these releases.' : materialChangeCount ? `${materialChangeCount} material package changes identified.` : 'No material changes were identified within Hansen’s scan coverage.';
    return {
      base: summary(base), target: summary(target), samePackage, signer, ...result, materialChangeCount, headline,
      metrics: {
        fileSize: target.fileSize - base.fileSize,
        dexFiles: target.packages.reduce((n,p) => n + p.dexFiles, 0) - base.packages.reduce((n,p) => n + p.dexFiles, 0),
        nativeLibraries: target.packages.reduce((n,p) => n + p.nativeLibraries, 0) - base.packages.reduce((n,p) => n + p.nativeLibraries, 0),
        configurationScore: target.assessment.safetyScore - base.assessment.safetyScore,
        telemetryScore: target.assessment.transparencyScore - base.assessment.transparencyScore,
      },
    };
  }
}
