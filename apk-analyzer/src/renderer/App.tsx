import { useEffect, useState } from 'react';
import DragDropZone from './components/DragDropZone';
import Settings from './components/Settings';
import AnalysisDashboard from './components/AnalysisDashboard';
import { AnalysisProgress, AnalysisReport, ReportSummary } from '../types';
export default function App() {
  const [view, setView] = useState<'analyze' | 'settings'>('analyze');
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [history, setHistory] = useState<ReportSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [reputationBusy, setReputationBusy] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress>({ step: 'Ready', status: 'completed' });
  const [error, setError] = useState('');
  const refresh = () => window.api.listReports().then(setHistory).catch(e => setError(String(e)));
  useEffect(() => { if (!window.api) return; void refresh(); return window.api.onAnalysisProgress(setProgress); }, []);
  const analyze = async (file: string) => {
    setBusy(true); setReport(null); setError(''); setView('analyze'); setProgress({ step: 'Starting inspection', status: 'running' });
    try { setReport(await window.api.analyzeApk(file)); await refresh(); }
    catch (e) { setError(e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': Error: /, '') : String(e)); }
    finally { setBusy(false); }
  };
  const open = async (id: string) => { try { setReport(await window.api.getReport(id)); setView('analyze'); setError(''); } catch (e) { setError(String(e)); } };
  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><span className="brand-icon">H</span><div>HANSEN<small>Android intelligence</small></div></div>
      <div className="nav-label">WORKSPACE</div><button className={`nav-item ${view === 'analyze' ? 'selected' : ''}`} onClick={() => setView('analyze')}>◈ &nbsp; Package inspector</button><button className={`nav-item ${view === 'settings' ? 'selected' : ''}`} onClick={() => setView('settings')}>⚙ &nbsp; Analysis settings</button>
      <div className="nav-label history-heading">RECENT REPORTS <span>{history.length}/20</span></div><div className="history-list">{history.length ? history.map(r => <button key={r.id} className={`history-item ${report?.id === r.id ? 'active' : ''}`} disabled={busy || reputationBusy} onClick={() => open(r.id)}><span className="mini-grade">{(r.malwareVerdict === "flagged-malicious" || r.malwareVerdict === "potentially-malicious") ? "!" : r.malwareVerdict === "no-evidence" ? r.grade : "?"}</span><span><strong>{r.packageName}</strong><small>{new Date(r.createdAt).toLocaleDateString()} · {r.fileName.toLowerCase().endsWith('.xapk') ? 'XAPK' : 'APK'}</small><small>{r.malwareTitle || "Malware not assessed"}</small></span></button>) : <p className="history-empty">Completed reports will appear here.</p>}</div>
      <div className="local-note"><span className="status-dot"/> Local static analysis<small>Packages are never installed or executed.</small></div>
    </aside>
    <div className="workspace"><header className="topbar"><span>Workspace <span className="slash">/</span> {view === 'settings' ? 'Settings' : 'Package inspector'}</span><span className="version">HANSEN · 1.0</span></header><main className="content">
      {!window.api && <div className="error" role="alert">Open Hansen in Electron to inspect files. This browser preview has no filesystem bridge.</div>}
      {error && <div className="error" role="alert">{error}<button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
      <div hidden={view !== 'analyze'}>
        {busy ? <section className="progress-card" aria-live="polite"><div className="spinner"/><p className="eyebrow">INSPECTION IN PROGRESS</p><h1>{progress.step}</h1><p>Large packages can take a few minutes. You can cancel at any time.</p><div className="progress-track"><span/></div><button className="secondary" onClick={() => window.api.cancelAnalysis().catch(e => setError(String(e)))}>Cancel analysis</button></section> : report ? <AnalysisDashboard report={report} onNew={() => setReport(null)} onBusy={setReputationBusy} onUpdate={r => { setReport(r); void refresh(); }}/> : <><div className="page-heading"><p className="eyebrow">LOOK INSIDE YOUR ANDROID APPS</p><h1>Understand what you install.</h1><p>Inspect an APK or XAPK and turn its contents into a clear, evidence-based report.</p></div><DragDropZone onFileSelected={analyze}/><div className="feature-grid"><section><span>01</span><h3>Inspect the package</h3><p>Read binary manifests, permissions, DEX code strings and native resources.</p></section><section><span>02</span><h3>Review the evidence</h3><p>Understand exposed components, telemetry indicators and areas worth a closer look.</p></section><section><span>03</span><h3>Keep a complete report</h3><p>Read findings here, revisit recent reports, and export a formatted PDF.</p></section></div><p className="scope-note">Static indicators support a review. They do not establish that an app is safe or malicious.</p></>}
      </div>
      {view === 'settings' && <Settings disabled={busy || reputationBusy}/>}
    </main></div>
  </div>;
}
