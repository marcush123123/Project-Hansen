import { useEffect, useState } from 'react';
import { AnalysisReport } from '../../types';
export default function AnalysisDashboard({ report, onNew, onUpdate, onBusy }: { report: AnalysisReport; onNew: () => void; onUpdate: (r: AnalysisReport) => void; onBusy: (value: boolean) => void }) {
  const [html, setHtml] = useState(''), [exporting, setExporting] = useState(false), [message, setMessage] = useState('');
  const [checking, setChecking] = useState(false);
  useEffect(() => { let disposed = false; setHtml(''); setMessage(''); window.api.getReportHtml(report.id).then(s => { if (!disposed) setHtml(s); }).catch(e => { if (!disposed) setMessage(String(e)); }); return () => { disposed = true; }; }, [report]);
  const reputationAction = async (sha256: string, action: 'lookup' | 'upload') => {
    setChecking(true); onBusy(true); setMessage('Waiting for VirusTotal or file confirmation. Requests may be spaced by 16 seconds.');
    try { onUpdate(await window.api.reputationAction(report.id, sha256, action)); }
    catch (error) { setMessage(String(error)); }
    finally { setChecking(false); onBusy(false); }
  };
  const exportPdf = async () => { setExporting(true); setMessage(''); try { const file = await window.api.exportPdf(report.id); setMessage(file ? `PDF saved to ${file}` : 'Export cancelled. Your report is still available here.'); } catch (e) { setMessage(`Export failed: ${String(e)}`); } finally { setExporting(false); } };
  return <div className="report-view"><div className="report-toolbar"><div><p className="eyebrow">INSPECTION COMPLETE</p><h1>Package report</h1><p>{report.context.packageName}</p></div><div className="toolbar-actions"><button className="secondary" disabled={checking} onClick={onNew}>New analysis</button><button className="primary" disabled={exporting || checking} onClick={exportPdf}>{exporting ? 'Creating PDF…' : 'Export PDF ↓'}</button></div></div>
    <section aria-label="Malware assessment" className={report.malware?.verdict === 'flagged-malicious' || report.malware?.verdict === 'potentially-malicious' ? 'error' : 'notice'}><h2>{report.malware?.title || 'Malware not assessed'}</h2><p>{report.malware?.detail || 'This older report has no malware assessment. Analyze the package again.'}</p></section>
    <details><summary>VirusTotal evidence and actions</summary><p>Requires a VirusTotal API key in Analysis settings. Upload sends the selected APK to VirusTotal after a separate confirmation; it may be retained and shared.</p>{report.reputation?.map(r => <section key={`${r.fileName}/${r.sha256}`}><h3>{r.fileName}</h3><p>{r.status}: {r.message}</p><p>SHA-256: {r.sha256}</p><button className="secondary" disabled={checking || exporting} onClick={() => reputationAction(r.sha256, 'lookup')}>{r.analysisId ? 'Check status' : 'Check hash'}</button> <button className="secondary" disabled={checking || exporting || !!r.analysisId} onClick={() => reputationAction(r.sha256, 'upload')}>Upload APK…</button></section>)}</details>
    {message && <p className="notice" role="status">{message}</p>}{checking && <button className="secondary" onClick={() => window.api.cancelAnalysis()}>Cancel request</button>}{html ? <iframe title="Complete package inspection report" className="report-frame" sandbox="" srcDoc={html}/> : <p role="status">Loading report…</p>}</div>;
}
