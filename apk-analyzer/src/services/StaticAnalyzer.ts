import { promises as fs } from 'fs';
import path from 'path';
import { MALWARE_PATTERNS } from './MalwareAssessment';
import { TRACKER_CATALOG } from './TrackerCatalog';
export const TRACKERS = TRACKER_CATALOG.map(t => t.id);
export class StaticAnalyzer {
  static async analyzeCode(dir: string) {
    const endpoints = new Set<string>(), apiKeys = new Set<string>(), trackerSDKs = new Set<string>(), suspiciousPatterns = new Set<string>();
    const evidence: Record<string, Set<string>> = {};
    let scannedFiles = 0, scannedBytes = 0, endpointsTruncated = false;
    const record = (key: string, file: string) => { evidence[key] ||= new Set(); if (evidence[key].size < 8) evidence[key].add(file); };
    const scan = (content: string, file: string) => {
      for (const match of content.matchAll(/https?:\/\/[a-zA-Z0-9][a-zA-Z0-9.\-:@%\[\]]{2,255}(?:\/[^\s"'<>\x00-\x20\\]{0,500})?/g)) {
        try {
          const u = new URL(match[0]);
          if (!u.hostname.includes('.') && u.hostname !== 'localhost') continue;
          // Only origins are retained: paths, query parameters, credentials and tokens are never reported.
          const origin = `${u.protocol}//${u.host}`;
          if (endpoints.size < 250 || endpoints.has(origin)) endpoints.add(origin); else endpointsTruncated = true;
        } catch { /* Not a valid URL. */ }
      }
      for (const sdk of TRACKERS) if (content.includes(sdk) || content.includes(sdk.replace(/\./g, '/'))) { trackerSDKs.add(sdk); record(sdk, file); }
      const patterns: [string, RegExp][] = [
        ...MALWARE_PATTERNS,
        ['Dynamic class loading reference', /DexClassLoader|InMemoryDexClassLoader/],
        ['Process execution reference', /Runtime[.;/]exec|ProcessBuilder|Ljava\/lang\/Runtime;/],
        ['Reflection reference', /java[./]lang[./]reflect/],
        ['JavaScript bridge reference', /addJavascriptInterface/],
      ];
      for (const [label, regex] of patterns) if (regex.test(content)) { suspiciousPatterns.add(label); record(label, file); }
      const secrets: [string, RegExp][] = [
        ['AWS access key pattern', /\bAKIA[A-Z0-9]{16}\b/],
        ['Google API key pattern', /AIza[0-9A-Za-z_-]{35}/],
        ['Private key marker', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
        ['Credential assignment pattern', /(?:api[_-]?key|secret|password)\s*[=:]\s*["'][A-Za-z0-9_\-]{20,}["']/i],
      ];
      for (const [label, regex] of secrets) if (regex.test(content)) { apiKeys.add(label); record(label, file); }
    };
    const walk = async (folder: string) => {
      for (const entry of await fs.readdir(folder, { withFileTypes: true })) {
        const full = path.join(folder, entry.name);
        if (entry.isDirectory()) { await walk(full); continue; }
        const file = path.relative(dir, full);
        const handle = await fs.open(full, 'r');
        let tail = '';
        try {
          const buffer = Buffer.alloc(1024 * 1024); let offset = 0;
          while (true) {
            const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
            if (!bytesRead) break;
            offset += bytesRead; scannedBytes += bytesRead;
            const content = tail + buffer.toString('latin1', 0, bytesRead);
            scan(content, file);
            // Also inspect UTF-16 resource string pools at either byte alignment.
            scan(new TextDecoder('utf-16le').decode(buffer.subarray(0, bytesRead - bytesRead % 2)), file);
            if (bytesRead > 1) scan(new TextDecoder('utf-16le').decode(buffer.subarray(1, bytesRead - (bytesRead - 1) % 2)), file);
            tail = content.slice(-1024);
          }
          scannedFiles++;
        } finally { await handle.close(); }
      }
    };
    await walk(dir);
    return { endpoints: [...endpoints].sort(), apiKeys: [...apiKeys].sort(), trackerSDKs: [...trackerSDKs].sort(), suspiciousPatterns: [...suspiciousPatterns].sort(), evidence: Object.fromEntries(Object.entries(evidence).map(([k,v]) => [k, [...v]])), scannedFiles, scannedBytes, endpointsTruncated };
  }
}
