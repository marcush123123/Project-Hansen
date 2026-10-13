import { contextBridge, ipcRenderer, webUtils } from 'electron';
import type { API } from '../types';
const api: API = {
  getPathForFile: file => webUtils.getPathForFile(file),
  reputationAction: (id, sha256, action) => ipcRenderer.invoke('reputation-action', id, sha256, action),
  analyzeApk: file => ipcRenderer.invoke('analyze-apk', file),
  cancelAnalysis: () => ipcRenderer.invoke('cancel-analysis'),
  onAnalysisProgress: callback => { const listener = (_: unknown, data: any) => callback(data); ipcRenderer.on('analysis-progress', listener); return () => ipcRenderer.removeListener('analysis-progress', listener); },
  onFindShortcut: callback => { const listener = () => callback(); ipcRenderer.on('find-shortcut', listener); return () => ipcRenderer.removeListener('find-shortcut', listener); },
  getSettings: () => ipcRenderer.invoke('get-settings'), saveSettings: settings => ipcRenderer.invoke('save-settings', settings),
  selectFile: () => ipcRenderer.invoke('select-file'), listReports: () => ipcRenderer.invoke('list-reports'),
  getReport: id => ipcRenderer.invoke('get-report', id), getReportHtml: id => ipcRenderer.invoke('get-report-html', id), exportPdf: id => ipcRenderer.invoke('export-pdf', id),
  compareReports: (baseId, targetId) => ipcRenderer.invoke('compare-reports', baseId, targetId),
  exportComparison: (baseId, targetId, format) => ipcRenderer.invoke('export-comparison', baseId, targetId, format),
  exportJson: id => ipcRenderer.invoke('export-json', id), exportSarif: id => ipcRenderer.invoke('export-sarif', id), deleteReport: id => ipcRenderer.invoke('delete-report', id),
  updateReportLabels: (ids, label) => ipcRenderer.invoke('update-report-labels', ids, label), deleteReports: ids => ipcRenderer.invoke('delete-reports', ids),
  updateReportPins: (ids, pinned) => ipcRenderer.invoke('update-report-pins', ids, pinned), reorderPinnedReports: ids => ipcRenderer.invoke('reorder-pinned-reports', ids),
  openExternal: url => ipcRenderer.invoke('open-external', url),
};
contextBridge.exposeInMainWorld('api', api);
