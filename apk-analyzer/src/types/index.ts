export interface AppSettings { virusTotalEnabled: boolean; virusTotalApiKey?: string; }
export const defaultSettings: AppSettings = { virusTotalEnabled: false, virusTotalApiKey: '' };
export interface Component {
  type: string; name: string; exported: boolean; exportReason: string; permission: string;
  readPermission?: string; writePermission?: string; grantUriPermissions?: boolean;
  intentActions?: string[]; intentCategories?: string[]; deepLinks?: string[];
}
export interface SigningCertificate {
  sha256: string; subject?: string; issuer?: string; serialNumber?: string;
  validFrom?: string; validTo?: string; publicKeyAlgorithm?: string;
}
export interface PackageSignature {
  status: 'signed' | 'unsigned' | 'unverified'; schemes: string[];
  certificates: SigningCertificate[]; artifactSha256?: string; detail: string;
}
export interface ManifestData {
  packageName: string; versionCode: string; versionName: string; split: string;
  minSdk: string; targetSdk: string; permissions: string[]; components: Component[];
  debuggable: boolean; allowBackup: boolean; usesCleartextTraffic: boolean; networkSecurityConfig: string; applicationPermission: string;
}
export interface Finding { id: string; severity: 'high' | 'medium' | 'low' | 'info'; title: string; detail: string; evidence: string[]; recommendation: string; }
export interface ContextJSON { packageName: string; versionCode: string; versionName: string; permissions: string[]; exportedActivities: string[]; exportedServices: string[]; endpoints: string[]; apiKeys: string[]; trackerSDKs: string[]; suspiciousPatterns: string[]; }
export interface AnalysisResult { grade: string; safetyScore: number; transparencyScore: number; telemetrySummary: string; threatModel: string; }
export interface PackageSummary { fileName: string; manifest: ManifestData; entries: number; dexFiles: number; nativeLibraries: number; sha256?: string; signature?: PackageSignature; }
export interface ReputationResult {
  sha256: string; fileName: string;
  status: 'not-checked' | 'not-found' | 'completed' | 'pending' | 'error';
  checkedAt?: string; analyzedAt?: string; analysisId?: string; message: string;
  stats?: Record<string, number>;
  detections?: { engine: string; category: string; label: string }[];
}
export interface MalwareAssessment {
  verdict: 'flagged-malicious' | 'potentially-malicious' | 'no-evidence' | 'inconclusive';
  title: string; detail: string; localFindings: Finding[]; ruleVersion: string;
}
export interface AnalysisReport {
  id: string; createdAt: string; fileName: string; fileSize: number; sha256: string;
  userLabel?: string;
  format: 'APK' | 'XAPK'; durationMs: number; packages: PackageSummary[];
  context: ContextJSON; findings: Finding[]; assessment: AnalysisResult;
  warnings: string[];
  malware?: MalwareAssessment; reputation?: ReputationResult[];
  coverage: { scannedFiles: number; scannedBytes: number; skippedFiles: number; endpointLimit: number; };
}
export interface AnalysisProgress { step: string; status: 'running' | 'completed' | 'error'; error?: string; }
export interface ReportSummary { id: string; packageName: string; fileName: string; createdAt: string; grade: string; userLabel?: string; pinned?: boolean; pinnedIndex?: number; versionCode?: string; versionName?: string; sha256?: string; signerFingerprint?: string; malwareTitle?: string; malwareVerdict?: MalwareAssessment['verdict']; }
export interface ChangeSet { added: string[]; removed: string[]; }
export interface ReportComparison {
  base: ReportSummary & { versionCode: string; versionName: string; sha256: string };
  target: ReportSummary & { versionCode: string; versionName: string; sha256: string };
  samePackage: boolean;
  signer: { status: 'same' | 'changed' | 'unknown'; detail: string; baseFingerprints: string[]; targetFingerprints: string[] };
  permissions: ChangeSet; trackers: ChangeSet; endpoints: ChangeSet; capabilities: ChangeSet;
  exportedComponents: ChangeSet; findings: ChangeSet; packages: ChangeSet;
  metrics: { fileSize: number; dexFiles: number; nativeLibraries: number; configurationScore: number; telemetryScore: number };
  headline: string; materialChangeCount: number;
}
export interface API {
  getPathForFile(file: File): string;
  analyzeApk(path: string): Promise<AnalysisReport>; cancelAnalysis(): Promise<void>;
  onAnalysisProgress(callback: (data: AnalysisProgress) => void): () => void;
  onFindShortcut(callback: () => void): () => void;
  getSettings(): Promise<AppSettings>; saveSettings(settings: AppSettings): Promise<void>;
  selectFile(): Promise<string | undefined>; listReports(): Promise<ReportSummary[]>;
  getReport(id: string): Promise<AnalysisReport>; getReportHtml(id: string): Promise<string>;
  exportPdf(id: string): Promise<string | null>;
  compareReports(baseId: string, targetId: string): Promise<ReportComparison>;
  exportComparison(baseId: string, targetId: string, format: 'json' | 'pdf'): Promise<string | null>;
  exportJson(id: string): Promise<string | null>; exportSarif(id: string): Promise<string | null>; deleteReport(id: string): Promise<void>;
  updateReportLabels(ids: string[], label: string): Promise<void>; deleteReports(ids: string[]): Promise<void>;
  updateReportPins(ids: string[], pinned: boolean): Promise<void>; reorderPinnedReports(ids: string[]): Promise<void>;
  openExternal(url: string): Promise<void>;
  reputationAction(id: string, sha256: string, action: 'lookup' | 'upload'): Promise<AnalysisReport>;
}
declare global { interface Window { api: API; } }
