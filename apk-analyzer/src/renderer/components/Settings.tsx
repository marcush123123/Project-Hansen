import { useEffect, useState } from 'react';
import { AppSettings, defaultSettings } from '../../types';

export default function Settings({ disabled, onSaved }: { disabled: boolean; onSaved?: (settings: AppSettings) => void }) {
  const [settings, setSettings] = useState<AppSettings>(defaultSettings), [saving, setSaving] = useState(false), [message, setMessage] = useState('');
  useEffect(() => { window.api?.getSettings().then(setSettings).catch(error => setMessage(String(error))); }, []);
  return <section className="settings-panel"><p className="eyebrow">OPTIONAL SERVICES</p><h1>Analysis settings</h1><p className="settings-intro">Configure optional malware reputation lookups.</p><form onSubmit={async event => { event.preventDefault(); setSaving(true); try { await window.api.saveSettings(settings); onSaved?.(settings); setMessage('Settings saved. They apply to your next analysis.'); } catch (error) { setMessage(String(error)); } finally { setSaving(false); } }}><fieldset disabled={disabled || saving || !window.api}>
    <h2>VirusTotal malware reputation</h2>
    <label htmlFor="vt-enabled">Default for new inspections</label><select id="vt-enabled" value={settings.virusTotalEnabled ? 'enabled' : 'disabled'} onChange={event => setSettings({ ...settings, virusTotalEnabled: event.target.value === 'enabled' })}><option value="disabled">Leave VirusTotal unchecked</option><option value="enabled">Check VirusTotal by default</option></select>
    <label htmlFor="vt-key">VirusTotal API key</label><input id="vt-key" type="password" autoComplete="off" required={settings.virusTotalEnabled} value={settings.virusTotalApiKey || ''} onChange={event => setSettings({ ...settings, virusTotalApiKey: event.target.value })}/>
    <p className="field-note">Before each inspection, you can choose whether to send APK SHA-256 hashes to VirusTotal, including contained APKs in XAPK files. Hash queries disclose your interest in those files. Up to four unique APKs are checked; remaining splits can be checked from the report. Requests are spaced to respect the public API rate limit.</p>
    <p className="field-note">Keys use the operating system key store where available, otherwise this session only. Full APK upload is optional and requires confirmation for each file. Uploaded files may be retained and shared by VirusTotal. Its public API is not licensed for commercial products; use an appropriate licensed account for commercial use.</p>
    <h2>Navigation history</h2>
    <label htmlFor="history-limit">Back-history pages to retain</label><select id="history-limit" value={settings.historyLimit} onChange={event => setSettings({ ...settings, historyLimit: Number(event.target.value) })}><option value={10}>10 pages</option><option value={25}>25 pages</option><option value={50}>50 pages</option><option value={100}>100 pages</option></select>
    <p className="field-note">The hold menu shows the 10 most recent pages. Use its ellipsis button to browse the complete retained history.</p>
    <button type="submit" className="primary">{saving ? 'Saving…' : 'Save settings'}</button>
  </fieldset>{disabled && <p>Settings can be changed after the current analysis finishes.</p>}{message && <p role="status" className="notice">{message}</p>}</form><p className="field-note">The latest 100 completed reports are stored in this app’s local user-data directory. Export PDF or JSON to keep a permanent copy.</p></section>;
}
