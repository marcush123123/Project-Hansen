import { useState } from 'react';
export default function DragDropZone({ onFileSelected, checkVirusTotal, onCheckVirusTotal }: { onFileSelected: (file: string) => void; checkVirusTotal: boolean; onCheckVirusTotal: (value: boolean) => void }) {
  const [dragging, setDragging] = useState(false), [error, setError] = useState(''), [selecting, setSelecting] = useState(false);
  const accept = (file: string) => { if (!/\.(apk|xapk)$/i.test(file)) { setError('Choose a file ending in .apk or .xapk.'); return; } setError(''); onFileSelected(file); };
  return <section className={`drop-zone ${dragging ? 'dragging' : ''}`} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={e => { e.preventDefault(); setDragging(false); if (e.dataTransfer.files.length !== 1) { setError('Please drop one APK or XAPK at a time.'); return; } const f = e.dataTransfer.files[0]; const filePath = window.api?.getPathForFile(f); if (!filePath) { setError('Open this application in Electron to drop local files.'); return; } accept(filePath); }}>
    <div className="upload-icon">↑</div><h2>Drop your Android package here</h2><p>APK or XAPK · up to 2 GiB · processed on your computer</p>
    <label className="scan-option"><input type="checkbox" checked={checkVirusTotal} onChange={event => onCheckVirusTotal(event.target.checked)}/><span><strong>Check VirusTotal after inspection</strong><small>Sends the APK's SHA-256 hash to VirusTotal. An API key is required.</small></span></label>
    <button className="primary" disabled={selecting || !window.api} onClick={async () => { setSelecting(true); try { const file = await window.api.selectFile(); if (file) accept(file); } catch (e) { setError(String(e)); } finally { setSelecting(false); } }}>{selecting ? 'Opening…' : 'Browse packages'} <span>↗</span></button>{error && <p role="alert" className="inline-error">{error}</p>}
  </section>;
}
