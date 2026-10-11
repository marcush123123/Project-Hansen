import { openAsBlob } from 'fs';
import { setTimeout as delay } from 'timers/promises';
import { ReputationResult } from '../types';

const API = 'https://www.virustotal.com/api/v3';
export const VT_UPLOAD_LIMIT = 650 * 1024 * 1024;
const categories = ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout', 'confirmed-timeout', 'failure', 'type-unsupported'];
export function parseFileReport(body: any, target: ReputationResult): ReputationResult {
  if (body?.data?.type !== 'file' || body.data.id !== target.sha256 || body.data.attributes?.sha256 !== target.sha256) throw new Error('VirusTotal returned a mismatched file identity');
  const a = body.data.attributes, stats: Record<string, number> = {};
  for (const category of categories) {
    const value = a.last_analysis_stats?.[category];
    if (!Number.isSafeInteger(value) || value < 0 || value > 10000) throw new Error('VirusTotal returned invalid analysis statistics');
    stats[category] = value;
  }
  if (!Number.isSafeInteger(a.last_analysis_date) || a.last_analysis_date <= 0 || a.last_analysis_date * 1000 > Date.now() + 300000) throw new Error('VirusTotal returned an invalid analysis date');
  const detections: NonNullable<ReputationResult['detections']> = [];
  if (!a.last_analysis_results || typeof a.last_analysis_results !== 'object') throw new Error('VirusTotal returned no engine results');
  const observed: Record<string, number> = Object.fromEntries(categories.map(c => [c, 0]));
  for (const [engine, value] of Object.entries(a.last_analysis_results).slice(0, 1000)) {
    const v = value as any;
    if (!v || !categories.includes(v.category)) throw new Error('VirusTotal returned invalid engine results');
    observed[v.category]++;
    if (['malicious', 'suspicious'].includes(v.category)) detections.push({ engine: engine.slice(0, 150), category: v.category, label: typeof v.result === 'string' ? v.result.slice(0, 300) : 'No label' });
  }
  if (categories.some(c => observed[c] !== stats[c])) throw new Error('VirusTotal statistics do not match its engine results');
  return { sha256: target.sha256, fileName: target.fileName, status: 'completed', checkedAt: new Date().toISOString(), analyzedAt: new Date(a.last_analysis_date * 1000).toISOString(), stats, detections,
    message: `${stats.malicious} malicious and ${stats.suspicious} suspicious engine detections. Undetected means no engine opinion, not a safe verdict.` };
}

export class VirusTotalService {
  private nextRequest = 0;
  constructor(private transport: typeof fetch = (input, init) => fetch(input, init), private spacingMs = 16000) {}

  private async request(url: string, apiKey: string, init: RequestInit = {}, signal?: AbortSignal): Promise<any> {
    if (!apiKey.trim()) throw new Error('Configure a VirusTotal API key in Analysis settings');
    const wait = Math.max(0, this.nextRequest - Date.now());
    if (wait) await delay(wait, undefined, { signal });
    signal?.throwIfAborted();
    this.nextRequest = Date.now() + this.spacingMs;
    const timeout = AbortSignal.timeout(init.method === 'POST' ? 120000 : 30000);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    let response: Response;
    try { response = await this.transport(url, { ...init, headers: { 'x-apikey': apiKey }, redirect: 'error', signal: combined }); }
    catch { throw new Error(combined.aborted ? 'VirusTotal request cancelled or timed out' : 'VirusTotal connection failed'); }
    if (response.status === 404) throw new Error('VT_NOT_FOUND');
    if (response.status === 401 || response.status === 403) throw new Error('VirusTotal rejected the API key or account permissions');
    if (response.status === 429) {
      const retry = Number(response.headers.get('retry-after'));
      this.nextRequest = Math.max(this.nextRequest, Date.now() + (Number.isFinite(retry) && retry > 0 ? Math.min(retry, 3600) : 60) * 1000);
      throw new Error('VirusTotal rate or daily quota limit reached. Try again later.');
    }
    if (!response.ok) throw new Error(`VirusTotal request failed (HTTP ${response.status})`);
    const text = await response.text();
    if (text.length > 4 * 1024 * 1024) throw new Error('VirusTotal response exceeds the supported size');
    try { return JSON.parse(text); } catch { throw new Error('VirusTotal returned invalid JSON'); }
  }

  async lookup(target: ReputationResult, key: string, signal?: AbortSignal): Promise<ReputationResult> {
    if (!/^[a-f0-9]{64}$/.test(target.sha256)) throw new Error('Invalid APK SHA-256');
    try {
      if (target.analysisId) {
        const analysis = await this.request(`${API}/analyses/${encodeURIComponent(target.analysisId)}`, key, {}, signal);
        if (analysis?.data?.id !== target.analysisId || analysis.data.type !== 'analysis') throw new Error('VirusTotal returned a mismatched analysis');
        const status = analysis.data.attributes?.status;
        if (status === 'queued' || status === 'in-progress') return { ...target, status: 'pending', message: 'VirusTotal analysis is still pending. Check again later.' };
        if (status !== 'completed') throw new Error('VirusTotal returned an invalid analysis status');
      }
      return parseFileReport(await this.request(`${API}/files/${target.sha256}`, key, {}, signal), target);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'VirusTotal lookup failed';
      // Retain previous positive evidence on network failures or pending rescans.
      return { ...target, status: message === 'VT_NOT_FOUND' ? (target.analysisId ? 'pending' : 'not-found') : 'error', checkedAt: new Date().toISOString(),
        message: message === 'VT_NOT_FOUND' ? 'No published VirusTotal report is available for this hash. This does not indicate safety.' : message };
    }
  }

  async upload(file: string, bytes: number, key: string, signal?: AbortSignal): Promise<string> {
    if (bytes <= 0 || bytes > VT_UPLOAD_LIMIT) throw new Error('VirusTotal uploads must be no larger than 650 MiB');
    let url = `${API}/files`;
    if (bytes > 32 * 1024 * 1024) {
      const body = await this.request(`${API}/files/upload_url`, key, {}, signal);
      const candidate = new URL(body?.data);
      if (candidate.protocol !== 'https:' || candidate.username || candidate.password || candidate.port || !(candidate.hostname === 'virustotal.com' || candidate.hostname.endsWith('.virustotal.com'))) throw new Error('VirusTotal returned an unsupported upload destination');
      url = candidate.href;
    }
    const form = new FormData();
    form.append('file', await openAsBlob(file), 'sample.apk');
    const body = await this.request(url, key, { method: 'POST', body: form }, signal);
    const id = body?.data?.id;
    if (body?.data?.type !== 'analysis' || typeof id !== 'string' || !/^[\w=:-]{1,500}$/.test(id)) throw new Error('Upload may have been accepted, but VirusTotal returned no valid analysis ID. Check the hash before retrying.');
    return id;
  }
}
