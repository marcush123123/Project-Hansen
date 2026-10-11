import { app, BrowserWindow, ipcMain, dialog, safeStorage } from 'electron';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';
import { Worker } from 'worker_threads';
import Store from 'electron-store';
import { AnalysisReport, LLMSettings, defaultSettings } from '../types';
import { ReportGenerator } from '../services/ReportGenerator';
import { renderPdf } from './pdf';

let mainWindow: BrowserWindow | null = null;
let store: Store;
let active: { worker: Worker; tempDir: string } | null = null;
let sessionKey = '';
const isDev = process.argv.includes('--dev') && !app.isPackaged;
const reportDir = () => path.join(app.getPath('userData'), 'reports');
function getSettings(): LLMSettings {
  const stored = store.get('settings', defaultSettings) as LLMSettings;
  let apiKey = sessionKey;
  const encrypted = store.get('encryptedApiKey') as string | undefined;
  if (encrypted && safeStorage.isEncryptionAvailable()) {
    try { apiKey = safeStorage.decryptString(Buffer.from(encrypted, 'base64')); } catch { /* Keychain changed; allow a fresh key. */ }
  }
  return { ...defaultSettings, ...stored, apiKey };
}
function validateSettings(value: unknown): LLMSettings {
  const s = value as LLMSettings;
  if (!s || !['offline','ollama','openai','anthropic','gemini'].includes(s.provider) || typeof s.modelName !== 'string' || s.modelName.length > 200 || typeof s.temperature !== 'number' || !Number.isFinite(s.temperature) || s.temperature < 0 || s.temperature > 1 || (s.apiKey !== undefined && (typeof s.apiKey !== 'string' || s.apiKey.length > 1000))) throw new Error('Invalid settings');
  if (s.provider !== 'offline' && !s.modelName.trim()) throw new Error('Enter a model name');
  return { provider: s.provider, modelName: s.modelName.trim(), temperature: s.temperature, apiKey: s.apiKey || '' };
}
async function listReports() {
  await fs.mkdir(reportDir(), { recursive: true });
  const reports: AnalysisReport[] = [];
  for (const file of await fs.readdir(reportDir())) {
    if (!/^[\da-f-]{36}\.json$/.test(file)) continue;
    try { reports.push(JSON.parse(await fs.readFile(path.join(reportDir(), file), 'utf8'))); } catch { /* Leave damaged files for inspection. */ }
  }
  return reports.sort((a,b) => b.createdAt.localeCompare(a.createdAt));
}
async function getReport(id: string): Promise<AnalysisReport> {
  if (typeof id !== 'string' || !/^[\da-f-]{36}$/.test(id)) throw new Error('Invalid report ID');
  return JSON.parse(await fs.readFile(path.join(reportDir(), `${id}.json`), 'utf8'));
}
async function cancel() { if (active) await active.worker.terminate(); }
function createWindow() {
  mainWindow = new BrowserWindow({ width: 1320, height: 920, minWidth: 850, minHeight: 640, title: 'Hansen', icon: path.join(app.getAppPath(), 'assets/icon.png'), backgroundColor: '#0d1926', webPreferences: { preload: path.join(__dirname, '../preload/preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
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
    const { apiKey, ...settings } = validateSettings(value);
    sessionKey = apiKey || '';
    store.delete('encryptedApiKey');
    if (sessionKey && safeStorage.isEncryptionAvailable() && safeStorage.getSelectedStorageBackend?.() !== 'basic_text') store.set('encryptedApiKey', safeStorage.encryptString(sessionKey).toString('base64'));
    store.set('settings', settings);
  });
  handle('select-file', async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { properties: ['openFile'], filters: [{ name: 'Android packages', extensions: ['apk','xapk'] }] });
    return result.canceled ? undefined : result.filePaths[0];
  });
  handle('analyze-apk', async (input: string) => {
    if (active) throw new Error('An analysis is already running');
    if (typeof input !== 'string' || !path.isAbsolute(input) || !/\.(apk|xapk)$/i.test(input)) throw new Error('Choose an APK or XAPK file');
    // Reserve before the first await so rapid requests cannot start two workers.
    let release: () => void = () => {};
    const reserved = { worker: { terminate: async () => { release(); } } as unknown as Worker, tempDir: '' };
    active = reserved;
    let cancelled = false; release = () => { cancelled = true; };
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hansen-'));
      reserved.tempDir = tempDir;
      if (cancelled) throw new Error('Analysis cancelled');
      const worker = new Worker(path.join(__dirname, 'analysisWorker.js'), { workerData: { input, settings: getSettings(), tempDir } });
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
      await fs.mkdir(reportDir(), { recursive: true });
      await fs.writeFile(path.join(reportDir(), `${report.id}.json`), JSON.stringify(report), { mode: 0o600 });
      for (const old of (await listReports()).slice(20)) await fs.rm(path.join(reportDir(), `${old.id}.json`), { force: true });
      return report;
    } finally {
      clearTimeout(timer);
      await reserved.worker.terminate();
      if (reserved.tempDir) await fs.rm(reserved.tempDir, { recursive: true, force: true });
      active = null;
    }
  });
  handle('cancel-analysis', cancel);
  handle('list-reports', async () => (await listReports()).map(r => ({ id: r.id, packageName: r.context.packageName, fileName: r.fileName, createdAt: r.createdAt, grade: r.assessment.grade })));
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
  if (active && !exiting) { event.preventDefault(); exiting = true; const job = active; void cancel().finally(async () => { if (job.tempDir) await fs.rm(job.tempDir, { recursive: true, force: true }); app.quit(); }); }
});
