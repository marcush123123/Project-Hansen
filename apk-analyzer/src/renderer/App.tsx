import { useEffect, useState } from 'react';
import DragDropZone from './components/DragDropZone';
import Settings from './components/Settings';
import AnalysisDashboard from './components/AnalysisDashboard';
import ComparisonDashboard from './components/ComparisonDashboard';
import HistoryList from './components/HistoryList';
import AboutSplash from './components/AboutSplash';
import FindBar from './components/FindBar';
import { AnalysisProgress, AnalysisReport, ReportSummary } from '../types';
export default function App() {
  const [view, setView] = useState<'analyze' | 'compare' | 'settings'>('analyze');
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [history, setHistory] = useState<ReportSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [reputationBusy, setReputationBusy] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress>({ step: 'Ready', status: 'completed' });
  const [error, setError] = useState('');
  const [aboutOpen, setAboutOpen] = useState(false);
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
    <aside className="sidebar"><button className="brand" type="button" onClick={() => setAboutOpen(true)} aria-label="About Hansen"><span className="brand-icon">H</span><span>HANSEN<small>Android intelligence</small></span></button>
      <div className="nav-label">WORKSPACE</div><button className={`nav-item ${view === 'analyze' ? 'selected' : ''}`} onClick={() => setView('analyze')}>◈ &nbsp; Package inspector</button><button className={`nav-item ${view === 'compare' ? 'selected' : ''}`} disabled={busy || reputationBusy} onClick={() => setView('compare')}>⇄ &nbsp; Compare releases</button><button className={`nav-item ${view === 'settings' ? 'selected' : ''}`} onClick={() => setView('settings')}>⚙ &nbsp; Analysis settings</button>
      <HistoryList reports={history} current={report} disabled={busy || reputationBusy} onOpen={open} onChanged={async (deleted = []) => { if (report && deleted.includes(report.id)) setReport(null); await refresh(); }}/>
      <div className="local-note"><span className="status-dot"/> Local static analysis<small>Packages are never installed or executed.</small></div>
    </aside>
    <div className="workspace"><header className="topbar"><span className="topbar-context">{view === 'settings' ? 'Analysis settings' : view === 'compare' ? 'Compare releases' : 'Package inspector'}</span>{(view === 'compare' || (view === 'analyze' && report)) && <FindBar surface={view === 'compare' ? 'compare' : 'report'}/>}<button type="button" className="version about-trigger" onClick={() => setAboutOpen(true)} aria-label="About Hansen">HANSEN · {__APP_VERSION__}</button></header><main className="content">
      {!window.api && <div className="error" role="alert">Open Hansen in Electron to inspect files. This browser preview has no filesystem bridge.</div>}
      {error && <div className="error" role="alert">{error}<button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
      <div hidden={view !== 'analyze'}>
        {busy ? <section className="progress-card" aria-live="polite"><div className="spinner"/><p className="eyebrow">INSPECTION IN PROGRESS</p><h1>{progress.step}</h1><p>Large packages can take a few minutes. You can cancel at any time.</p><div className="progress-track"><span/></div><button className="secondary" onClick={() => window.api.cancelAnalysis().catch(e => setError(String(e)))}>Cancel analysis</button></section> : report ? <AnalysisDashboard report={report} onNew={() => setReport(null)} onBusy={setReputationBusy} onUpdate={r => { setReport(r); void refresh(); }} onDelete={() => { setReport(null); void refresh(); }}/> : <><div className="page-heading"><p className="eyebrow">LOOK INSIDE YOUR ANDROID APPS</p><h1>Understand what you install.</h1><p>Inspect an APK or XAPK and view its contents as a clear, evidence-based report.</p></div><DragDropZone onFileSelected={analyze}/><div className="feature-grid"><section><span>01</span><h3>Inspect the package</h3><p>Read binary manifests, permissions, DEX code strings and native resources.</p></section><section><span>02</span><h3>Review the evidence</h3><p>Understand exposed components, telemetry indicators and areas worth a closer look.</p></section><section><span>03</span><h3>Compare releases</h3><p>See changes to signing identity, permissions, trackers, endpoints and exposed components.</p></section></div><p className="scope-note">Static indicators support a review. They do not establish that an app is safe or malicious.</p></>}
      </div>
      {view === 'compare' && <ComparisonDashboard reports={history}/>}
      {view === 'settings' && <Settings disabled={busy || reputationBusy}/>}
    </main></div>{aboutOpen && <AboutSplash onClose={() => setAboutOpen(false)}/>}
  </div>;
}
