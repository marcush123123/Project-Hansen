import { app, BrowserWindow, ipcMain, dialog, safeStorage } from 'electron';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';
import { Worker } from 'worker_threads';
import Store from 'electron-store';
import { AnalysisReport, LLMSettings, defaultSettings } from '../types';
import { ReportGenerator } from '../services/ReportGenerator';
import { renderPdf } from './pdf';
import { VirusTotalService } from '../services/VirusTotalService';
import { updateMalwareAssessment } from '../services/MalwareAssessment';
import { prepareUpload } from '../services/UploadSnapshot';

let mainWindow: BrowserWindow | null = null;
let store: Store;
let active: { worker: Worker; tempDir: string } | null = null;
let sessionKey = '';
let sessionVirusTotalKey = '';
let reputationBusy = false;
let reputationFinished: Promise<void> | null = null;
let networkController: AbortController | null = null;
const virusTotal = new VirusTotalService();
const isDev = process.argv.includes('--dev') && !app.isPackaged;
app.setName('Hansen');
const reportDir = () => path.join(app.getPath('userData'), 'reports');
function getSettings(): LLMSettings {
  const stored = store.get('settings', defaultSettings) as LLMSettings;
  let apiKey = sessionKey;
  const encrypted = store.get('encryptedApiKey') as string | undefined;
  if (encrypted && safeStorage.isEncryptionAvailable()) {
    try { apiKey = safeStorage.decryptString(Buffer.from(encrypted, 'base64')); } catch { /* Keychain changed; allow a fresh key. */ }
  }
  let virusTotalApiKey = sessionVirusTotalKey;
  const encryptedVT = store.get('encryptedVirusTotalApiKey') as string | undefined;
  if (encryptedVT && safeStorage.isEncryptionAvailable()) {
    try { virusTotalApiKey = safeStorage.decryptString(Buffer.from(encryptedVT, 'base64')); } catch { /* Request a new key. */ }
  }
  return { ...defaultSettings, ...stored, apiKey, virusTotalApiKey };
}
function validateSettings(value: unknown): LLMSettings {
  const s = value as LLMSettings;
  if (!s || !['offline','ollama','openai','anthropic','gemini'].includes(s.provider) || typeof s.modelName !== 'string' || s.modelName.length > 200 || typeof s.temperature !== 'number' || !Number.isFinite(s.temperature) || s.temperature < 0 || s.temperature > 1 || (s.apiKey !== undefined && (typeof s.apiKey !== 'string' || s.apiKey.length > 1000))) throw new Error('Invalid settings');
  if (s.provider !== 'offline' && !s.modelName.trim()) throw new Error('Enter a model name');
  if (s.virusTotalEnabled !== undefined && typeof s.virusTotalEnabled !== 'boolean') throw new Error('Invalid VirusTotal setting');
  if (s.virusTotalApiKey !== undefined && (typeof s.virusTotalApiKey !== 'string' || s.virusTotalApiKey.length > 1000)) throw new Error('Invalid VirusTotal API key');
  if (s.virusTotalEnabled && !s.virusTotalApiKey?.trim()) throw new Error('Enter a VirusTotal API key');
  return { provider: s.provider, modelName: s.modelName.trim(), temperature: s.temperature, apiKey: s.apiKey || '', virusTotalEnabled: !!s.virusTotalEnabled, virusTotalApiKey: s.virusTotalApiKey?.trim() || '' };
}
async function listReports() {
  await fs.mkdir(reportDir(), { recursive: true });
  const reports: AnalysisReport[] = [];
  for (const file of await fs.readdir(reportDir())) {
    if (!/^[\da-f-]{36}\.json$/.test(file)) continue;
    try {
      const report = JSON.parse(await fs.readFile(path.join(reportDir(), file), 'utf8'));
      if (report.malware) updateMalwareAssessment(report);
      reports.push(report);
    } catch { /* Leave damaged files for inspection. */ }
  }
  return reports.sort((a,b) => b.createdAt.localeCompare(a.createdAt));
}
async function getReport(id: string): Promise<AnalysisReport> {
  if (typeof id !== 'string' || !/^[\da-f-]{36}$/.test(id)) throw new Error('Invalid report ID');
  const report = JSON.parse(await fs.readFile(path.join(reportDir(), `${id}.json`), 'utf8'));
  if (report.malware) updateMalwareAssessment(report);
  return report;
}
async function saveReport(report: AnalysisReport) {
  await fs.mkdir(reportDir(), { recursive: true });
  const file = path.join(reportDir(), `${report.id}.json`);
  await fs.writeFile(`${file}.tmp`, JSON.stringify(report), { mode: 0o600 });
  await fs.rename(`${file}.tmp`, file);
}
async function cancel() { networkController?.abort(); if (active) await active.worker.terminate(); }
function createWindow() {
  mainWindow = new BrowserWindow({ width: 1320, height: 920, minWidth: 850, minHeight: 640, title: 'Hansen', icon: path.join(app.getAppPath(), 'assets/icon.png'), backgroundColor: '#070708', webPreferences: { preload: path.join(__dirname, '../preload/preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', event => event.preventDefault());
  mainWindow.on('closed', () => { mainWindow = null; void cancel(); });
  if (isDev) void mainWindow.loadURL('http://127.0.0.1:5173');
  else void mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
}
app.whenReady().then(() => {
  store = new Store();
  // Migrate the scaffold's plaintext key to OS encryption when available.
  const previous = store.get('settings') as LLMSettings | undefined;
  if (previous?.apiKey) {
    sessionKey = previous.apiKey;
    if (safeStorage.isEncryptionAvailable() && safeStorage.getSelectedStorageBackend?.() !== 'basic_text') store.set('encryptedApiKey', safeStorage.encryptString(sessionKey).toString('base64'));
    const { apiKey, ...rest } = previous; store.set('settings', rest);
  }
  const handle = (channel: string, fn: (...args: any[]) => any) => ipcMain.handle(channel, (event, ...args) => {
    if (!mainWindow || event.sender !== mainWindow.webContents || event.senderFrame !== mainWindow.webContents.mainFrame) throw new Error('Untrusted IPC sender');
    return fn(...args);
  });
  handle('get-settings', getSettings);
  handle('save-settings', (value: unknown) => {
    if (active || reputationBusy) throw new Error('Wait for the current analysis to finish');
    const { apiKey, virusTotalApiKey, ...settings } = validateSettings(value);
    sessionKey = apiKey || '';
    store.delete('encryptedApiKey');
    if (sessionKey && safeStorage.isEncryptionAvailable() && safeStorage.getSelectedStorageBackend?.() !== 'basic_text') store.set('encryptedApiKey', safeStorage.encryptString(sessionKey).toString('base64'));
    sessionVirusTotalKey = virusTotalApiKey || '';
    store.delete('encryptedVirusTotalApiKey');
    if (sessionVirusTotalKey && safeStorage.isEncryptionAvailable() && safeStorage.getSelectedStorageBackend?.() !== 'basic_text') store.set('encryptedVirusTotalApiKey', safeStorage.encryptString(sessionVirusTotalKey).toString('base64'));
    store.set('settings', settings);
  });
  handle('select-file', async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { properties: ['openFile'], filters: [{ name: 'Android packages', extensions: ['apk','xapk'] }] });
    return result.canceled ? undefined : result.filePaths[0];
  });
  handle('analyze-apk', async (input: string) => {
    if (active || reputationBusy) throw new Error('An analysis is already running');
    if (typeof input !== 'string' || !path.isAbsolute(input) || !/\.(apk|xapk)$/i.test(input)) throw new Error('Choose an APK or XAPK file');
    // Reserve before the first await so rapid requests cannot start two workers.
    let release: () => void = () => {};
    const reserved = { worker: { terminate: async () => { release(); } } as unknown as Worker, tempDir: '' };
    active = reserved;
    const settings = getSettings();
    const controller = new AbortController();
    networkController = controller;
    let cancelled = false; release = () => { cancelled = true; };
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hansen-'));
      reserved.tempDir = tempDir;
      if (cancelled) throw new Error('Analysis cancelled');
      const { virusTotalApiKey, ...workerSettings } = settings;
      const worker = new Worker(path.join(__dirname, 'analysisWorker.js'), { workerData: { input, settings: workerSettings, tempDir } });
      reserved.worker = worker;
      const report = await new Promise<AnalysisReport>((resolve, reject) => {
        timer = setTimeout(() => { void worker.terminate(); reject(new Error('Analysis exceeded the 10 minute time limit')); }, 10 * 60 * 1000);
        worker.on('message', message => {
          if (message.progress) mainWindow?.webContents.send('analysis-progress', message.progress);
          if (message.report) resolve(message.report);
          if (message.error) reject(new Error(message.error));
        });
        worker.once('error', reject);
        worker.once('exit', () => reject(new Error('Analysis cancelled or worker stopped')));
      });
      clearTimeout(timer);
      if (settings.virusTotalEnabled && settings.virusTotalApiKey) {
        // Bound automatic work to one public-API minute. Every other split stays explicitly unchecked.
        const unique = [...new Map((report.reputation || []).map(r => [r.sha256, r])).values()].slice(0, 4);
        for (const target of unique) {
          controller.signal.throwIfAborted();
          mainWindow?.webContents.send('analysis-progress', { step: `Checking VirusTotal: ${target.fileName}`, status: 'running' });
          const result = await virusTotal.lookup(target, settings.virusTotalApiKey, controller.signal);
          report.reputation = report.reputation!.map(r => r.sha256 === result.sha256 ? { ...result, fileName: r.fileName } : r);
          if (result.status === 'error') break;
        }
      }
      controller.signal.throwIfAborted();
      updateMalwareAssessment(report);
      await saveReport(report);
      for (const old of (await listReports()).slice(20)) await fs.rm(path.join(reportDir(), `${old.id}.json`), { force: true });
      return report;
    } finally {
      clearTimeout(timer);
      try {
        await reserved.worker.terminate();
        if (reserved.tempDir) await fs.rm(reserved.tempDir, { recursive: true, force: true });
      } finally { active = null; networkController = null; }
    }
  });
  handle('cancel-analysis', cancel);
  handle('list-reports', async () => (await listReports()).map(r => ({ id: r.id, packageName: r.context.packageName, fileName: r.fileName, createdAt: r.createdAt, grade: r.assessment.grade, malwareTitle: r.malware?.title || 'Malware not assessed', malwareVerdict: r.malware?.verdict })));
  handle('reputation-action', async (id: string, sha256: string, action: string) => {
    if (active || reputationBusy) throw new Error('An analysis is already running');
    if (!['lookup', 'upload'].includes(action) || typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sha256)) throw new Error('Invalid reputation action');
    const settings = getSettings();
    if (!settings.virusTotalEnabled || !settings.virusTotalApiKey) throw new Error('Enable VirusTotal and enter its API key in Analysis settings');
    reputationBusy = true;
    let finish: () => void = () => {};
    reputationFinished = new Promise<void>(resolve => { finish = resolve; });
    const controller = new AbortController(); networkController = controller;
    let tempDir = '';
    try {
      const report = await getReport(id);
      const target = report.reputation?.find(r => r.sha256 === sha256);
      if (!target) throw new Error('No APK hash is available. Analyze this package again.');
      let result = target;
      if (action === 'lookup') result = await virusTotal.lookup(target, settings.virusTotalApiKey, controller.signal);
      else {
        const choice = await dialog.showOpenDialog(mainWindow!, { title: 'Select the original package for this report', properties: ['openFile'], filters: [{ name: 'Original Android package', extensions: [report.format.toLowerCase()] }] });
        if (choice.canceled || !choice.filePaths[0]) return report;
        tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hansen-upload-'));
        const snapshot = await prepareUpload(choice.filePaths[0], report, target, tempDir);
        controller.signal.throwIfAborted();
        const confirmation = await dialog.showMessageBox(mainWindow!, {
          type: 'warning', title: 'Upload APK to VirusTotal?', message: `Upload ${target.fileName} (${(snapshot.bytes / 1024 ** 2).toFixed(2)} MiB)?`,
          detail: `SHA-256: ${target.sha256}\n\nThis sends the complete APK to VirusTotal. Submitted files can be retained and shared with security vendors and the research community. Do not submit confidential software. For XAPK files, only this selected APK is uploaded. This cannot be undone by Hansen.`,
          buttons: ['Cancel', 'Upload APK'], defaultId: 0, cancelId: 0, noLink: true,
        });
        if (confirmation.response !== 1) return report;
        controller.signal.throwIfAborted();
        const analysisId = await virusTotal.upload(snapshot.file, snapshot.bytes, settings.virusTotalApiKey, controller.signal);
        result = { ...target, status: 'pending', analysisId, checkedAt: new Date().toISOString(), message: 'Upload accepted. Use Check status to retrieve the analysis. Previous detections, if present, remain visible.' };
      }
      report.reputation = report.reputation!.map(r => r.sha256 === sha256 ? { ...result, fileName: r.fileName } : r);
      updateMalwareAssessment(report);
      await saveReport(report);
      return report;
    } finally {
      try { if (tempDir) await fs.rm(tempDir, { recursive: true, force: true }); }
      finally { reputationBusy = false; networkController = null; reputationFinished = null; finish(); }
    }
  });
  handle('get-report', getReport);
  handle('get-report-html', async (id: string) => ReportGenerator.buildHtmlReport(await getReport(id)));
  handle('export-pdf', async (id: string) => {
    const report = await getReport(id);
    const result = await dialog.showSaveDialog(mainWindow!, { defaultPath: `${report.context.packageName.replace(/[^\w.-]/g, '_')}-hansen.pdf`, filters: [{ name: 'PDF report', extensions: ['pdf'] }] });
    if (result.canceled || !result.filePath) return null;
    const destination = /\.pdf$/i.test(result.filePath) ? result.filePath : `${result.filePath}.pdf`;
    await renderPdf(report, destination);
    return destination;
  });
  createWindow();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (!mainWindow) createWindow(); });
let exiting = false;
app.on('before-quit', event => {
  networkController?.abort();
  if ((active || reputationBusy) && !exiting) {
    event.preventDefault(); exiting = true;
    const job = active, pending = reputationFinished;
    void cancel().finally(async () => {
      try { if (job?.tempDir) await fs.rm(job.tempDir, { recursive: true, force: true }); await pending; }
      finally { app.quit(); }
    });
  }
});
