import { BrowserWindow } from 'electron';
import { promises as fs } from 'fs';
import { AnalysisReport } from '../types';
import { ReportGenerator } from '../services/ReportGenerator';
export async function renderPdf(report: AnalysisReport, destination: string): Promise<void> {
  return renderHtmlPdf(ReportGenerator.buildHtmlReport(report), destination);
}
export async function renderHtmlPdf(html: string, destination: string): Promise<void> {
  const win = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, javascript: false } });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  try {
    await win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    const pdf = await win.webContents.printToPDF({ printBackground: true, pageSize: 'A4', margins: { top: 0.55, bottom: 0.6, left: 0.5, right: 0.5 }, displayHeaderFooter: true, headerTemplate: '<span></span>', footerTemplate: '<div style="font-size:8px;width:100%;text-align:center;color:#607080">Hansen · <span class="pageNumber"></span> / <span class="totalPages"></span></div>' });
    await fs.writeFile(destination, pdf);
  } finally { win.destroy(); }
}
