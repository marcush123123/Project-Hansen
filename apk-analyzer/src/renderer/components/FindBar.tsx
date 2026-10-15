import { KeyboardEvent, useEffect, useRef, useState } from 'react';

type SearchSurface = 'report' | 'compare';
export interface FindViewState { query: string; current: number; summoned: boolean; }

const searchRoot = (surface: SearchSurface): { root: Node; selection: Selection | null } | null => {
  if (surface === 'report') {
    const frame = document.querySelector<HTMLIFrameElement>('.report-frame'), doc = frame?.contentDocument;
    return doc?.body ? { root: doc.body, selection: doc.getSelection() } : null;
  }
  const root = document.querySelector('.comparison-view');
  return root ? { root, selection: window.getSelection() } : null;
};

const collectMatches = (root: Node, query: string): Range[] => {
  const doc = root.ownerDocument || document, walker = doc.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: node => node.parentElement?.closest('script, style, input, textarea, select') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
  });
  const needle = query.toLocaleLowerCase(), ranges: Range[] = [];
  let node: Node | null;
  while ((node = walker.nextNode())) {
    const text = node.textContent || '', haystack = text.toLocaleLowerCase();
    let offset = 0;
    while (needle && (offset = haystack.indexOf(needle, offset)) >= 0) {
      const range = doc.createRange(); range.setStart(node, offset); range.setEnd(node, offset + query.length); ranges.push(range); offset += Math.max(query.length, 1);
    }
  }
  return ranges;
};

const comparisonHighlights = () => (window.CSS as typeof CSS & { highlights?: Map<string, unknown> }).highlights;
const clearComparisonHighlights = () => { comparisonHighlights()?.delete('hansen-find-all'); comparisonHighlights()?.delete('hansen-find-current'); };

export default function FindBar({ surface, initialState, onStateChange }: { surface: SearchSurface; initialState?: FindViewState; onStateChange?: (state: FindViewState) => void }) {
  const input = useRef<HTMLInputElement>(null), ranges = useRef<Range[]>([]), firstIndex = useRef(initialState?.current ?? 0);
  const [query, setQuery] = useState(initialState?.query || ''), [current, setCurrent] = useState(initialState?.current ?? -1), [count, setCount] = useState(0), [summoned, setSummoned] = useState(initialState?.summoned || false);
  const show = (index: number, rebuild = false) => {
    const target = searchRoot(surface);
    if (!target || !query.trim()) { ranges.current = []; setCount(0); setCurrent(-1); target?.selection?.removeAllRanges(); clearComparisonHighlights(); return; }
    if (rebuild) ranges.current = collectMatches(target.root, query);
    const total = ranges.current.length; setCount(total);
    if (!total) { setCurrent(-1); target.selection?.removeAllRanges(); clearComparisonHighlights(); return; }
    const next = ((index % total) + total) % total, range = ranges.current[next];
    if (surface === 'compare' && comparisonHighlights() && 'Highlight' in window) {
      const HighlightConstructor = (window as unknown as { Highlight: new (...ranges: Range[]) => unknown }).Highlight;
      comparisonHighlights()!.set('hansen-find-all', new HighlightConstructor(...ranges.current));
      comparisonHighlights()!.set('hansen-find-current', new HighlightConstructor(range));
    } else { target.selection?.removeAllRanges(); target.selection?.addRange(range); }
    range.startContainer.parentElement?.scrollIntoView({ block: 'center', behavior: 'smooth' }); setCurrent(next);
  };
  useEffect(() => { const index = firstIndex.current; firstIndex.current = 0; const timer = window.setTimeout(() => show(index, true), 80); return () => window.clearTimeout(timer); }, [query, surface]);
  useEffect(() => { onStateChange?.({ query, current, summoned }); }, [query, current, summoned, onStateChange]);
  useEffect(() => {
    if (surface !== 'report') return;
    const restore = () => { if (query) window.setTimeout(() => show(current >= 0 ? current : 0, true), 0); };
    window.addEventListener('hansen-report-loaded', restore);
    return () => window.removeEventListener('hansen-report-loaded', restore);
  }, [surface, query, current]);
  useEffect(() => {
    const key = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f') { event.preventDefault(); setSummoned(true); input.current?.focus(); input.current?.select(); }
      if (event.key === 'Escape') { setQuery(''); setSummoned(false); input.current?.blur(); }
    };
    const targets: Window[] = [window], frames: HTMLIFrameElement[] = [];
    const attachReport = () => {
      const frame = document.querySelector<HTMLIFrameElement>('.report-frame'), target = frame?.contentWindow;
      if (frame && !frames.includes(frame)) { frame.addEventListener('load', attachReport); frames.push(frame); }
      if (target) { target.addEventListener('keydown', key); if (!targets.includes(target)) targets.push(target); }
    };
    attachReport();
    const observer = new MutationObserver(attachReport); observer.observe(document.body, { childList: true, subtree: true });
    const removeShortcut = window.api.onFindShortcut(() => { setSummoned(true); input.current?.focus(); input.current?.select(); });
    return () => { clearComparisonHighlights(); removeShortcut(); observer.disconnect(); frames.forEach(frame => frame.removeEventListener('load', attachReport)); targets.forEach(target => target.removeEventListener('keydown', key)); };
  }, [surface]);
  const keyboard = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter' || event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault(); show(current + (event.shiftKey || event.key === 'ArrowUp' ? -1 : 1), false);
    }
  };
  const change = (value: string) => { firstIndex.current = 0; setQuery(value); setSummoned(!!value); };
  return <div className={`find-bar ${query || summoned ? 'floating' : ''}`} role="search"><span aria-hidden="true">⌕</span><input ref={input} value={query} onFocus={() => setSummoned(true)} onBlur={() => { if (!query) setSummoned(false); }} onChange={event => change(event.target.value)} onKeyDown={keyboard} aria-label="Find in current view" placeholder="Find in view…"/><span className="find-count" aria-live="polite">{query ? (count ? `${current + 1}/${count}` : '0/0') : ''}</span><button type="button" onClick={() => show(current - 1)} disabled={!count} aria-label="Previous match">↑</button><button type="button" onClick={() => show(current + 1)} disabled={!count} aria-label="Next match">↓</button><button type="button" onClick={() => { setQuery(''); setSummoned(false); input.current?.blur(); }} disabled={!query} aria-label="Clear search">×</button></div>;
}
