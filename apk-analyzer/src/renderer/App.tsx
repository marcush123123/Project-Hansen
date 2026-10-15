import { useEffect, useRef, useState } from 'react';
import DragDropZone from './components/DragDropZone';
import Settings from './components/Settings';
import AnalysisDashboard from './components/AnalysisDashboard';
import ComparisonDashboard, { ComparisonViewState } from './components/ComparisonDashboard';
import HistoryList from './components/HistoryList';
import AboutSplash from './components/AboutSplash';
import FindBar, { FindViewState } from './components/FindBar';
import { AnalysisProgress, AnalysisReport, AppSettings, defaultSettings, ReportSummary } from '../types';
import hansenLogo from '../../assets/logo.png';
export default function App() {
  const [view, setView] = useState<'analyze' | 'compare' | 'settings'>('analyze');
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [history, setHistory] = useState<ReportSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [reputationBusy, setReputationBusy] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress>({ step: 'Ready', status: 'completed' });
  const [error, setError] = useState('');
  const [aboutOpen, setAboutOpen] = useState(false);
  const [scanVirusTotal, setScanVirusTotal] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  type Page = { view: 'analyze' | 'compare' | 'settings'; reportId?: string; label: string; comparison?: ComparisonViewState; find?: FindViewState };
  const backStack = useRef<Page[]>([]), forwardStack = useRef<Page[]>([]), holdTimer = useRef<number | undefined>(undefined), heldBack = useRef(false);
  const comparisonSnapshot = useRef<ComparisonViewState>({ baseId: '', targetId: '', comparison: null }), findSnapshot = useRef<FindViewState>({ query: '', current: -1, summoned: false });
  const [comparisonRestore, setComparisonRestore] = useState<ComparisonViewState>(comparisonSnapshot.current), [findRestore, setFindRestore] = useState<FindViewState>(findSnapshot.current);
  const [historyVersion, setHistoryVersion] = useState(0), [historyMenu, setHistoryMenu] = useState(false), [historyDialog, setHistoryDialog] = useState(false), [restoreToken, setRestoreToken] = useState(0);
  const refresh = () => window.api.listReports().then(setHistory).catch(e => setError(String(e)));
  useEffect(() => { if (!window.api) return; void refresh(); window.api.getSettings().then(value => { setSettings(value); setScanVirusTotal(value.virusTotalEnabled); }).catch(() => {}); return window.api.onAnalysisProgress(setProgress); }, []);
  const currentPage = (): Page => ({ view, reportId: view === 'analyze' ? report?.id : undefined, label: view === 'settings' ? 'Analysis settings' : view === 'compare' ? 'Compare releases' : report ? (report.userLabel || report.context.packageName) : 'New package', comparison: view === 'compare' ? { ...comparisonSnapshot.current } : undefined, find: (view === 'compare' || (view === 'analyze' && report)) ? { ...findSnapshot.current } : undefined });
  const showPage = async (page: Page) => {
    const nextComparison = page.comparison || { baseId: '', targetId: '', comparison: null }, nextFind = page.find || { query: '', current: -1, summoned: false };
    comparisonSnapshot.current = nextComparison; findSnapshot.current = nextFind;
    setComparisonRestore(nextComparison); setFindRestore(nextFind); setRestoreToken(value => value + 1);
    setHistoryMenu(false); setError(''); setView(page.view);
    if (page.view === 'analyze') setReport(page.reportId ? await window.api.getReport(page.reportId) : null);
  };
  const pushHistory = (stack: Page[], page: Page) => { stack.push(page); if (stack.length > settings.historyLimit) stack.splice(0, stack.length - settings.historyLimit); };
  const navigate = async (page: Page) => { pushHistory(backStack.current, currentPage()); forwardStack.current = []; setHistoryVersion(v => v + 1); try { await showPage(page); } catch (e) { setError(String(e)); } };
  const travel = async (direction: 'back' | 'forward') => {
    const from = direction === 'back' ? backStack.current : forwardStack.current, to = direction === 'back' ? forwardStack.current : backStack.current;
    const page = from.pop(); if (!page) return; pushHistory(to, currentPage()); setHistoryVersion(v => v + 1); try { await showPage(page); } catch (e) { setError(String(e)); }
  };
  const goBackTo = async (index: number) => { while (backStack.current.length - 1 > index) pushHistory(forwardStack.current, backStack.current.pop()!); setHistoryDialog(false); await travel('back'); };
  const describePage = (page: Page) => {
    let description = page.label;
    if (page.view === 'compare' && page.comparison?.comparison) {
      const { base, target } = page.comparison.comparison;
      description = `Comparison: ${base.packageName} ${base.versionName || base.versionCode} → ${target.packageName} ${target.versionName || target.versionCode}`;
    } else if (page.view === 'analyze' && page.reportId) description = `Package report: ${page.label}`;
    if (page.find?.query) description += ` · Find “${page.find.query}”${page.find.current >= 0 ? ` at match ${page.find.current + 1}` : ''}`;
    return description;
  };
  const backPages = backStack.current.map((page, index) => ({ page, index, description: describePage(page) })).reverse();
  const menuBackPages = backPages.slice(0, 10);
  const analyze = async (file: string) => {
    if (scanVirusTotal && !settings.virusTotalApiKey?.trim()) { await navigate({ view: 'settings', label: 'Analysis settings' }); setError('Add your VirusTotal API key before enabling the VirusTotal check.'); return; }
    setBusy(true); setReport(null); setError(''); setView('analyze'); setProgress({ step: 'Starting inspection', status: 'running' });
    try { setReport(await window.api.analyzeApk(file, scanVirusTotal)); await refresh(); }
    catch (e) { setError(e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': Error: /, '') : String(e)); }
    finally { setBusy(false); }
  };
  const open = async (id: string) => { const item = history.find(r => r.id === id); await navigate({ view: 'analyze', reportId: id, label: item?.userLabel || item?.packageName || 'Package report' }); };
  const openSettings = async () => navigate({ view: 'settings', label: 'Analysis settings' });
  return <div className="app-shell">
    <aside className="sidebar"><button className="brand" type="button" onClick={() => setAboutOpen(true)} aria-label="About Hansen"><img className="brand-icon" src={hansenLogo} alt=""/><span>HANSEN<small>Android intelligence</small></span></button>
      <div className="nav-label">WORKSPACE</div><button className={`nav-item ${view === 'analyze' && !report ? 'selected' : ''}`} onClick={() => void navigate({ view: 'analyze', label: 'New package' })}>◈ &nbsp; {view === 'analyze' && report ? 'New package' : 'Package inspector'}</button><button className={`nav-item ${view === 'compare' ? 'selected' : ''}`} disabled={busy || reputationBusy} onClick={() => void navigate({ view: 'compare', label: 'Compare releases' })}>⇄ &nbsp; Compare releases</button><button className={`nav-item ${view === 'settings' ? 'selected' : ''}`} onClick={() => void openSettings()}>⚙ &nbsp; Analysis settings</button>
      <HistoryList reports={history} current={report} disabled={busy || reputationBusy} onOpen={open} onChanged={async (deleted = []) => { if (report && deleted.includes(report.id)) setReport(null); await refresh(); }}/>
      <div className="local-note"><span className="status-dot"/> Local static analysis<small>Packages are never installed or executed.</small></div>
    </aside>
    <div className="workspace"><header className="topbar"><span className="topbar-context">{view === 'settings' ? 'Analysis settings' : view === 'compare' ? 'Compare releases' : report ? 'Package report' : 'Package inspector'}</span><div className="topbar-tools"><div className="page-history"><button type="button" disabled={!backStack.current.length} aria-label="Go back" title="Go back (hold for history)" onClick={() => { if (heldBack.current) { heldBack.current = false; return; } void travel('back'); }} onPointerDown={() => { heldBack.current = false; holdTimer.current = window.setTimeout(() => { heldBack.current = true; setHistoryMenu(true); }, 450); }} onPointerUp={() => window.clearTimeout(holdTimer.current)} onPointerLeave={() => window.clearTimeout(holdTimer.current)}>←</button><button type="button" disabled={!forwardStack.current.length} aria-label="Go forward" title="Go forward" onClick={() => void travel('forward')}>→</button>{historyMenu && <div className="history-menu" role="menu" aria-label="Back history">{menuBackPages.map(item => <button type="button" role="menuitem" title={item.description} key={`${item.index}-${item.description}`} onClick={() => void goBackTo(item.index)}>{item.description}</button>)}{backPages.length > 10 && <button type="button" className="history-more" aria-label="Show complete back history" onClick={() => { setHistoryMenu(false); setHistoryDialog(true); }}>…</button>}</div>}</div>{(view === 'compare' || (view === 'analyze' && report)) && <FindBar key={`find-${restoreToken}`} surface={view === 'compare' ? 'compare' : 'report'} initialState={findRestore} onStateChange={state => { findSnapshot.current = state; }}/>}</div></header><main className="content" onClick={() => historyMenu && setHistoryMenu(false)} data-history-version={historyVersion}>
      {!window.api && <div className="error" role="alert">Open Hansen in Electron to inspect files. This browser preview has no filesystem bridge.</div>}
      {error && <div className="error" role="alert">{error}<button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
      <div hidden={view !== 'analyze'}>
        {busy ? <section className="progress-card" aria-live="polite"><div className="spinner"/><p className="eyebrow">INSPECTION IN PROGRESS</p><h1>{progress.step}</h1><p>Large packages can take a few minutes. You can cancel at any time.</p><div className="progress-track"><span/></div><button className="secondary" onClick={() => window.api.cancelAnalysis().catch(e => setError(String(e)))}>Cancel analysis</button></section> : report ? <AnalysisDashboard report={report} settings={settings} onSettings={openSettings} onNew={() => void navigate({ view: 'analyze', label: 'New package' })} onBusy={setReputationBusy} onUpdate={r => { setReport(r); void refresh(); }} onDelete={() => { setReport(null); void refresh(); }}/> : <><div className="page-heading"><p className="eyebrow">LOOK INSIDE YOUR ANDROID APPS</p><h1>Understand what you install.</h1><p>Inspect an APK or XAPK and view its contents as a clear, evidence-based report.</p></div><DragDropZone onFileSelected={analyze} checkVirusTotal={scanVirusTotal} onCheckVirusTotal={setScanVirusTotal}/><div className="feature-grid"><section><span>01</span><h3>Inspect the package</h3><p>Read binary manifests, permissions, DEX code strings and native resources.</p></section><section><span>02</span><h3>Review the evidence</h3><p>Understand exposed components, telemetry indicators and areas worth a closer look.</p></section><section><span>03</span><h3>Compare releases</h3><p>See changes to signing identity, permissions, trackers, endpoints and exposed components.</p></section></div><p className="scope-note">Static indicators support a review. They do not establish that an app is safe or malicious.</p></>}
      </div>
      {view === 'compare' && <ComparisonDashboard
        key={`compare-${restoreToken}`}
        reports={history}
        initialState={comparisonRestore}
        onStateChange={state => { comparisonSnapshot.current = state; }}
      />}
      {view === 'settings' && <Settings
        disabled={busy || reputationBusy}
        onSaved={value => { setSettings(value); setScanVirusTotal(value.virusTotalEnabled); backStack.current = backStack.current.slice(-value.historyLimit); forwardStack.current = forwardStack.current.slice(-value.historyLimit); setHistoryVersion(version => version + 1); }}
      />}
    </main></div>
    {historyDialog && <div className="history-dialog-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) setHistoryDialog(false); }}><section className="history-dialog" role="dialog" aria-modal="true" aria-labelledby="history-dialog-title"><button type="button" className="history-dialog-close" onClick={() => setHistoryDialog(false)} aria-label="Close back history">×</button><p className="eyebrow">NAVIGATION</p><h2 id="history-dialog-title">Complete back history</h2><p>{backPages.length} of {settings.historyLimit} retained pages</p><div className="history-dialog-list">{backPages.map(item => <button type="button" title={item.description} key={`${item.index}-${item.description}`} onClick={() => void goBackTo(item.index)}>{item.description}</button>)}</div></section></div>}
    {aboutOpen && <AboutSplash onClose={() => setAboutOpen(false)}/>}
  </div>;
}
