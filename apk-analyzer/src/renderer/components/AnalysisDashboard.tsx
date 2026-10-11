import { useEffect, useState } from 'react';
import { AnalysisReport } from '../../types';
export default function AnalysisDashboard({ report, onNew }: { report: AnalysisReport; onNew: () => void }) {
  const [html, setHtml] = useState(''), [exporting, setExporting] = useState(false), [message, setMessage] = useState('');
  useEffect(() => { let disposed = false; setHtml(''); setMessage(''); window.api.getReportHtml(report.id).then(s => { if (!disposed) setHtml(s); }).catch(e => { if (!disposed) setMessage(String(e)); }); return () => { disposed = true; }; }, [report.id]);
  const exportPdf = async () => { setExporting(true); setMessage(''); try { const file = await window.api.exportPdf(report.id); setMessage(file ? `PDF saved to ${file}` : 'Export cancelled. Your report is still available here.'); } catch (e) { setMessage(`Export failed: ${String(e)}`); } finally { setExporting(false); } };
  return <div className="report-view"><div className="report-toolbar"><div><p className="eyebrow">INSPECTION COMPLETE</p><h1>Package report</h1><p>{report.context.packageName}</p></div><div className="toolbar-actions"><button className="secondary" onClick={onNew}>New analysis</button><button className="primary" disabled={exporting} onClick={exportPdf}>{exporting ? 'Creating PDF…' : 'Export PDF ↓'}</button></div></div>{message && <p className="notice" role="status">{message}</p>}{html ? <iframe title="Complete package inspection report" className="report-frame" sandbox="" srcDoc={html}/> : <p role="status">Loading report…</p>}</div>;
}
