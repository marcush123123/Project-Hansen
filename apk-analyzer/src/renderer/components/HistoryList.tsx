import { DragEvent, MouseEvent, useMemo, useState } from 'react';
import { AnalysisReport, ReportSummary } from '../../types';

interface Props { reports: ReportSummary[]; current: AnalysisReport | null; disabled: boolean; onOpen: (id: string) => void; onChanged: (deleted?: string[]) => Promise<void>; }
export default function HistoryList({ reports, current, disabled, onOpen, onChanged }: Props) {
  const [query, setQuery] = useState(''), [selecting, setSelecting] = useState(false), [selected, setSelected] = useState<Set<string>>(new Set()), [anchor, setAnchor] = useState<string>();
  const [labels, setLabels] = useState<Record<string, string | null>>({}), [hidden, setHidden] = useState<Set<string>>(new Set()), [dragging, setDragging] = useState<string>();
  const labelFor = (report: ReportSummary) => report.id in labels ? labels[report.id] || undefined : report.userLabel;
  const available = useMemo(() => reports.filter(report => !hidden.has(report.id)), [reports, hidden]);
  const visible = useMemo(() => { const q = query.trim().toLowerCase(); return q ? available.filter(r => [labelFor(r), r.packageName, r.fileName, r.versionName, r.malwareTitle].some(v => v?.toLowerCase().includes(q))) : available; }, [available, query, labels]);
  const finish = () => { setSelecting(false); setSelected(new Set()); setAnchor(undefined); };
  const choose = (event: MouseEvent, id: string) => {
    if (!selecting && !event.ctrlKey && !event.metaKey && !event.shiftKey) { onOpen(id); return; }
    if (!selecting) setSelecting(true);
    const next = new Set(selected);
    if (event.shiftKey && anchor) {
      const a = visible.findIndex(r => r.id === anchor), b = visible.findIndex(r => r.id === id);
      if (a >= 0 && b >= 0) for (let i = Math.min(a,b); i <= Math.max(a,b); i++) next.add(visible[i].id);
    } else if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next); setAnchor(id);
  };
  const selectAll = () => {
    const ids = visible.map(report => report.id), allSelected = ids.length > 0 && ids.every(id => selected.has(id)), next = new Set(selected);
    for (const id of ids) allSelected ? next.delete(id) : next.add(id);
    setSelected(next); setAnchor(undefined);
  };
  const edit = async () => {
    const label = window.prompt(`Set a label for ${selected.size} selected report${selected.size === 1 ? '' : 's'}. Leave blank to clear existing labels.`, selected.size === 1 ? reports.find(r => selected.has(r.id))?.userLabel || '' : '');
    if (label === null) return;
    try { await window.api.updateReportLabels([...selected], label); setLabels(currentLabels => ({ ...currentLabels, ...Object.fromEntries([...selected].map(id => [id, label.trim() || null])) })); finish(); void onChanged(); } catch (error) { window.alert(`Could not update reports: ${String(error)}`); }
  };
  const setPinned = async (pinned: boolean) => {
    const ids = [...selected].filter(id => !!reports.find(report => report.id === id)?.pinned !== pinned);
    if (!ids.length) return;
    try { await window.api.updateReportPins(ids, pinned); finish(); void onChanged(); } catch (error) { window.alert(`Could not ${pinned ? 'pin' : 'unpin'} reports: ${String(error)}`); }
  };
  const remove = async () => {
    if (!window.confirm(`Permanently delete ${selected.size} selected report${selected.size === 1 ? '' : 's'}? This cannot be undone.`)) return;
    const ids = [...selected];
    try { await window.api.deleteReports(ids); setHidden(currentHidden => new Set([...currentHidden, ...ids])); finish(); void onChanged(ids); } catch (error) { window.alert(`Could not delete reports: ${String(error)}`); }
  };
  const dropPin = async (event: DragEvent, target: string) => {
    event.preventDefault();
    if (!dragging || dragging === target) return setDragging(undefined);
    const order = reports.filter(report => report.pinned).map(report => report.id), from = order.indexOf(dragging), to = order.indexOf(target);
    if (from < 0 || to < 0) return setDragging(undefined);
    order.splice(to, 0, order.splice(from, 1)[0]); setDragging(undefined);
    try { await window.api.reorderPinnedReports(order); void onChanged(); } catch (error) { window.alert(`Could not reorder pinned reports: ${String(error)}`); }
  };
  const availableCount = available.length, ids = visible.map(report => report.id), allSelected = ids.length > 0 && ids.every(id => selected.has(id));
  const selectedPinned = [...selected].filter(id => reports.find(report => report.id === id)?.pinned).length;
  const selectedUnpinned = selected.size - selectedPinned, pinnedCount = reports.filter(report => report.pinned).length;
  return <><div className="nav-label history-heading"><span>RECENT REPORTS <b>{availableCount}/100</b></span>{availableCount > 0 && <button className="history-select-toggle" disabled={disabled} onClick={() => selecting ? finish() : setSelecting(true)}>{selecting ? 'Done' : 'Select'}</button>}</div>
    {selecting && <div className="history-actions"><span>{selected.size} selected</span><button disabled={!visible.length || disabled} onClick={selectAll}>{allSelected ? 'Clear all' : 'Select all'}</button><button disabled={!selectedUnpinned || pinnedCount + selectedUnpinned > 5 || disabled} title="Pin up to 5 reports" onClick={() => setPinned(true)}>Pin</button><button disabled={!selectedPinned || disabled} onClick={() => setPinned(false)}>Unpin</button><button disabled={!selected.size || disabled} onClick={edit}>Edit label</button><button className="danger-text" disabled={!selected.size || disabled} onClick={remove}>Delete</button></div>}
    {availableCount > 4 && <input className="history-search" aria-label="Filter saved reports" placeholder="Filter reports…" value={query} onChange={e => setQuery(e.target.value)}/>}<div className={`history-list ${selecting ? 'selecting' : ''}`}>{visible.length ? visible.map((r, index) => { const label = labelFor(r), firstPinned = r.pinned && !visible.slice(0, index).some(report => report.pinned), firstRecent = !r.pinned && !visible.slice(0, index).some(report => !report.pinned); return <div className="history-row" key={r.id}>{firstPinned && <div className="history-group-label">PINNED · DRAG TO REORDER</div>}{firstRecent && reports.some(report => report.pinned) && <div className="history-group-label">RECENT</div>}<button draggable={!!r.pinned && !selecting && !query} onDragStart={event => { setDragging(r.id); event.dataTransfer.effectAllowed = 'move'; }} onDragEnd={() => setDragging(undefined)} onDragOver={event => { if (r.pinned && dragging) event.preventDefault(); }} onDrop={event => void dropPin(event, r.id)} className={`history-item ${current?.id === r.id && !selecting ? 'active' : ''} ${selected.has(r.id) ? 'checked' : ''} ${r.pinned ? 'pinned' : ''} ${dragging === r.id ? 'dragging' : ''}`} disabled={disabled} onClick={event => choose(event, r.id)} aria-pressed={selecting ? selected.has(r.id) : undefined}>{selecting && <span className="history-checkbox" aria-hidden="true">{selected.has(r.id) ? '✓' : ''}</span>}<span className="mini-grade">{(r.malwareVerdict === 'flagged-malicious' || r.malwareVerdict === 'potentially-malicious') ? '!' : r.malwareVerdict === 'no-evidence' ? r.grade : '?'}</span><span><strong>{label || r.packageName}</strong>{label && <small>{r.packageName}</small>}<small>v{r.versionName || '?'} · {new Date(r.createdAt).toLocaleDateString()} · {r.fileName.toLowerCase().endsWith('.xapk') ? 'XAPK' : 'APK'}</small><small>{r.malwareTitle || 'Malware not assessed'}</small></span>{r.pinned && <span className="pin-badge" aria-label="Pinned">◆</span>}</button></div>; }) : <p className="history-empty">{query ? 'No reports match this filter.' : 'Completed reports will appear here.'}</p>}</div></>;
}
