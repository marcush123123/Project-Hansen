import { contextBridge, ipcRenderer, webUtils } from 'electron';
import type { API } from '../types';
const api: API = {
  getPathForFile: file => webUtils.getPathForFile(file),
  reputationAction: (id, sha256, action) => ipcRenderer.invoke('reputation-action', id, sha256, action),
  analyzeApk: file => ipcRenderer.invoke('analyze-apk', file),
  cancelAnalysis: () => ipcRenderer.invoke('cancel-analysis'),
  onAnalysisProgress: callback => { const listener = (_: unknown, data: any) => callback(data); ipcRenderer.on('analysis-progress', listener); return () => ipcRenderer.removeListener('analysis-progress', listener); },
  getSettings: () => ipcRenderer.invoke('get-settings'), saveSettings: settings => ipcRenderer.invoke('save-settings', settings),
  selectFile: () => ipcRenderer.invoke('select-file'), listReports: () => ipcRenderer.invoke('list-reports'),
  getReport: id => ipcRenderer.invoke('get-report', id), getReportHtml: id => ipcRenderer.invoke('get-report-html', id), exportPdf: id => ipcRenderer.invoke('export-pdf', id),
};
contextBridge.exposeInMainWorld('api', api);
