export interface LLMSettings { provider: 'offline' | 'ollama' | 'openai' | 'anthropic' | 'gemini'; apiKey?: string; modelName: string; temperature: number; }
export const defaultSettings: LLMSettings = { provider: 'offline', modelName: 'llama3', temperature: 0.2 };
export interface Component { type: string; name: string; exported: boolean; exportReason: string; permission: string; }
export interface ManifestData {
  packageName: string; versionCode: string; versionName: string; split: string;
  minSdk: string; targetSdk: string; permissions: string[]; components: Component[];
  debuggable: boolean; allowBackup: boolean; usesCleartextTraffic: boolean; networkSecurityConfig: string; applicationPermission: string;
}
export interface Finding { id: string; severity: 'high' | 'medium' | 'low' | 'info'; title: string; detail: string; evidence: string[]; recommendation: string; }
export interface ContextJSON { packageName: string; versionCode: string; versionName: string; permissions: string[]; exportedActivities: string[]; exportedServices: string[]; endpoints: string[]; apiKeys: string[]; trackerSDKs: string[]; suspiciousPatterns: string[]; }
export interface AnalysisResult { grade: string; safetyScore: number; transparencyScore: number; telemetrySummary: string; threatModel: string; }
export interface PackageSummary { fileName: string; manifest: ManifestData; entries: number; dexFiles: number; nativeLibraries: number; }
export interface AnalysisReport {
  id: string; createdAt: string; fileName: string; fileSize: number; sha256: string;
  format: 'APK' | 'XAPK'; durationMs: number; packages: PackageSummary[];
  context: ContextJSON; findings: Finding[]; assessment: AnalysisResult;
  ai?: AnalysisResult; aiProvider?: string; warnings: string[];
  coverage: { scannedFiles: number; scannedBytes: number; skippedFiles: number; endpointLimit: number; };
}
export interface AnalysisProgress { step: string; status: 'running' | 'completed' | 'error'; error?: string; }
export interface ReportSummary { id: string; packageName: string; fileName: string; createdAt: string; grade: string; }
export interface API {
  getPathForFile(file: File): string;
  analyzeApk(path: string): Promise<AnalysisReport>; cancelAnalysis(): Promise<void>;
  onAnalysisProgress(callback: (data: AnalysisProgress) => void): () => void;
  getSettings(): Promise<LLMSettings>; saveSettings(settings: LLMSettings): Promise<void>;
  selectFile(): Promise<string | undefined>; listReports(): Promise<ReportSummary[]>;
  getReport(id: string): Promise<AnalysisReport>; getReportHtml(id: string): Promise<string>;
  exportPdf(id: string): Promise<string | null>;
}
declare global { interface Window { api: API; } }
