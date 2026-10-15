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
    // Chromium otherwise leaves the page-margin canvas white even though the
    // report body is dark. Paint the root canvas so margins and page gaps use
    // the same background as the printable report.
    await win.webContents.insertCSS('@page { size: A4; margin: 0.55in 0.5in 0.6in; background: #222126; } html { background: #222126 !important; } @media print { html, body { background: #222126 !important; } }');
    const pdf = await win.webContents.printToPDF({ printBackground: true, pageSize: 'A4', preferCSSPageSize: true, margins: { top: 0, bottom: 0, left: 0, right: 0 }, displayHeaderFooter: true, headerTemplate: '<span></span>', footerTemplate: '<div style="font-size:8px;width:100%;text-align:center;color:#889095">Hansen · <span class="pageNumber"></span> / <span class="totalPages"></span></div>' });
    await fs.writeFile(destination, pdf);
  } finally { win.destroy(); }
}
