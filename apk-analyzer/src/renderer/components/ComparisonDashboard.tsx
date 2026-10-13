import { useEffect, useMemo, useState } from 'react';
import { ChangeSet, ReportComparison, ReportSummary } from '../../types';

const ChangeGroup = ({ title, changes }: { title: string; changes: ChangeSet }) => <section className="change-group">
  <h3>{title}<span>{changes.added.length + changes.removed.length}</span></h3>
  {!changes.added.length && !changes.removed.length ? <p className="unchanged">No changes</p> : <div className="change-columns">
    <div><strong className="added">+ Added</strong>{changes.added.length ? <ul>{changes.added.map(x => <li key={`a-${x}`}>{x}</li>)}</ul> : <p>None</p>}</div>
    <div><strong className="removed">− Removed</strong>{changes.removed.length ? <ul>{changes.removed.map(x => <li key={`r-${x}`}>{x}</li>)}</ul> : <p>None</p>}</div>
  </div>}
</section>;
const delta = (value: number, suffix = '') => `${value > 0 ? '+' : ''}${value.toLocaleString()}${suffix}`;

export default function ComparisonDashboard({ reports }: { reports: ReportSummary[] }) {
  const [baseId, setBaseId] = useState(''), [targetId, setTargetId] = useState(''), [comparison, setComparison] = useState<ReportComparison | null>(null), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const groups = useMemo(() => [...new Set(reports.map(r => r.packageName))].sort(), [reports]);
  useEffect(() => { if (reports.length < 2 || baseId || targetId) return; const newest = reports[0], match = reports.slice(1).find(r => r.packageName === newest.packageName); if (match) { setBaseId(match.id); setTargetId(newest.id); } }, [reports, baseId, targetId]);
  const compare = async () => { setBusy(true); setError(''); try { setComparison(await window.api.compareReports(baseId, targetId)); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } };
  const exportComparison = async (format: 'json' | 'pdf') => { setBusy(true); setError(''); try { await window.api.exportComparison(baseId, targetId, format); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } };
  if (reports.length < 2) return <section className="empty-state"><p className="eyebrow">VERSION INTELLIGENCE</p><h1>Compare package releases</h1><p>Analyze at least two packages to compare permissions, signing identity, trackers, endpoints, exposed components, and package composition.</p></section>;
  const optionGroups = groups.map(pkg => <optgroup key={pkg} label={pkg}>{reports.filter(r => r.packageName === pkg).map(r => <option key={r.id} value={r.id}>{r.versionName || 'Unknown version'} ({r.versionCode || '?'}) · {new Date(r.createdAt).toLocaleString()}</option>)}</optgroup>);
  return <div className="comparison-view"><div className="page-heading"><p className="eyebrow">VERSION INTELLIGENCE</p><h1>What changed?</h1><p>Compare two saved reports. For an update review, choose the older release first and the newer release second.</p></div>
    <section className="compare-picker"><label>Previous report<select value={baseId} onChange={e => { setBaseId(e.target.value); setComparison(null); }}><option value="">Choose a report</option>{optionGroups}</select></label><span className="compare-arrow">→</span><label>New report<select value={targetId} onChange={e => { setTargetId(e.target.value); setComparison(null); }}><option value="">Choose a report</option>{optionGroups}</select></label><button className="primary" disabled={busy || !baseId || !targetId || baseId === targetId} onClick={compare}>{busy ? 'Comparing…' : 'Compare releases'}</button></section>
    {error && <p className="error">{error}</p>}
    {comparison && <><section className={`comparison-headline ${comparison.signer.status === 'changed' || !comparison.samePackage ? 'danger' : ''}`}><p className="eyebrow">{comparison.base.versionName || comparison.base.versionCode} → {comparison.target.versionName || comparison.target.versionCode}</p><h2>{comparison.headline}</h2><p>{comparison.signer.detail}</p><div className="comparison-actions"><button className="secondary" disabled={busy} onClick={() => exportComparison('json')}>Export comparison JSON</button><button className="primary" disabled={busy} onClick={() => exportComparison('pdf')}>Export comparison PDF</button></div></section>
      <div className="metric-grid"><section><span>Configuration score</span><strong>{delta(comparison.metrics.configurationScore)}</strong></section><section><span>Telemetry score</span><strong>{delta(comparison.metrics.telemetryScore)}</strong></section><section><span>Package size</span><strong>{delta(Math.round(comparison.metrics.fileSize / 1024), ' KiB')}</strong></section><section><span>DEX files</span><strong>{delta(comparison.metrics.dexFiles)}</strong></section><section><span>Native libraries</span><strong>{delta(comparison.metrics.nativeLibraries)}</strong></section><section><span>Signer</span><strong>{comparison.signer.status}</strong></section></div>
      <div className="change-grid"><ChangeGroup title="Permissions" changes={comparison.permissions}/><ChangeGroup title="Exported components" changes={comparison.exportedComponents}/><ChangeGroup title="Trackers" changes={comparison.trackers}/><ChangeGroup title="Network origins" changes={comparison.endpoints}/><ChangeGroup title="Code capabilities" changes={comparison.capabilities}/><ChangeGroup title="Findings" changes={comparison.findings}/><ChangeGroup title="Package splits" changes={comparison.packages}/></div>
      <p className="scope-note">A comparison only reflects evidence captured by each Hansen report. Missing or changed evidence can result from scanner-version differences as well as package changes.</p></>}
  </div>;
}
