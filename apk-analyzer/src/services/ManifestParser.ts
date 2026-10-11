import { promises as fs } from 'fs';
import path from 'path';
import { parseStringPromise } from 'xml2js';
import { ManifestData } from '../types';
type XmlNode = { name: string; attrs: Record<string, string>; children: XmlNode[] };
// Android ResXMLTree chunks and typed attributes; never executes package contents.
export function decodeBinaryXml(buf: Buffer): XmlNode {
  const check = (offset: number, length: number, end = buf.length) => {
    if (offset < 0 || length < 0 || offset + length > end) throw new Error('Truncated binary Android manifest');
  };
  check(0, 8);
  if (buf.readUInt16LE(0) !== 3 || buf.readUInt32LE(4) !== buf.length) throw new Error('Invalid binary XML header');
  let strings: string[] = [], root: XmlNode | undefined;
  const stack: XmlNode[] = [];
  for (let pos = buf.readUInt16LE(2); pos < buf.length;) {
    check(pos, 8);
    const type = buf.readUInt16LE(pos), header = buf.readUInt16LE(pos + 2), size = buf.readUInt32LE(pos + 4);
    if (header < 8 || size < header) throw new Error('Invalid Android XML chunk');
    check(pos, size);
    const end = pos + size;
    if (type === 1) {
      check(pos, 28, end);
      const count = buf.readUInt32LE(pos + 8), flags = buf.readUInt32LE(pos + 16), start = buf.readUInt32LE(pos + 20);
      check(pos + header, count * 4, end);
      strings = [];
      for (let i = 0; i < count; i++) {
        let p = pos + start + buf.readUInt32LE(pos + header + i * 4);
        const length = (utf8: boolean) => {
          check(p, utf8 ? 1 : 2, end);
          let n = utf8 ? buf[p++] : buf.readUInt16LE(p);
          if (!utf8) p += 2;
          if (n & (utf8 ? 0x80 : 0x8000)) {
            check(p, utf8 ? 1 : 2, end);
            n = utf8 ? ((n & 0x7f) << 8) | buf[p++] : ((n & 0x7fff) * 65536) + buf.readUInt16LE(p);
            if (!utf8) p += 2;
          }
          return n;
        };
        const utf8 = !!(flags & 0x100);
        let n = length(utf8);
        if (utf8) n = length(true);
        check(p, n * (utf8 ? 1 : 2), end);
        strings.push(new TextDecoder(utf8 ? 'utf-8' : 'utf-16le', { fatal: true }).decode(buf.subarray(p, p + n * (utf8 ? 1 : 2))));
      }
    } else if (type === 0x102) {
      check(pos + header, 20, end);
      const ext = pos + header;
      const stringAt = (i: number) => { if (i >= strings.length) throw new Error('Invalid Android XML string index'); return strings[i]; };
      const node: XmlNode = { name: stringAt(buf.readUInt32LE(ext + 4)), attrs: {}, children: [] };
      const attrStart = buf.readUInt16LE(ext + 8), attrSize = buf.readUInt16LE(ext + 10), count = buf.readUInt16LE(ext + 12);
      if (attrSize < 20) throw new Error('Invalid Android XML attribute');
      check(ext + attrStart, count * attrSize, end);
      for (let i = 0; i < count; i++) {
        const a = ext + attrStart + i * attrSize;
        const ns = buf.readUInt32LE(a), name = stringAt(buf.readUInt32LE(a + 4)), raw = buf.readUInt32LE(a + 8);
        const kind = buf[a + 15], data = buf.readUInt32LE(a + 16);
        const value = raw !== 0xffffffff ? stringAt(raw) : kind === 3 ? stringAt(data) : kind === 0x12 ? String(data !== 0) : kind === 1 ? `@0x${data.toString(16)}` : String(data);
        const key = ns !== 0xffffffff && stringAt(ns) === 'http://schemas.android.com/apk/res/android' ? `android:${name}` : name;
        node.attrs[key] = value;
      }
      if (stack.length) stack[stack.length - 1].children.push(node);
      else { if (root) throw new Error('Multiple manifest roots'); root = node; }
      stack.push(node);
    } else if (type === 0x103) {
      check(pos + header, 8, end);
      const node = stack.pop();
      if (!node || strings[buf.readUInt32LE(pos + header + 4)] !== node.name) throw new Error('Unbalanced Android XML');
    }
    pos = end;
  }
  if (!root || stack.length) throw new Error('Incomplete Android XML');
  return root;
}
export class ManifestParser {
  static async parseManifest(dir: string, defaults?: ManifestData): Promise<ManifestData> { return this.parse(await fs.readFile(path.join(dir, 'AndroidManifest.xml')), defaults); }
  static async parse(buf: Buffer, defaults?: ManifestData): Promise<ManifestData> {
    if (buf.length < 8) throw new Error('Manifest is empty or truncated');
    let root: XmlNode;
    if (buf.readUInt16LE(0) === 3) root = decodeBinaryXml(buf);
    else {
      const text = buf.toString('utf8');
      if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw new Error('DTD/entity declarations are not supported');
      const xml = await parseStringPromise(text, { explicitArray: true });
      const convert = (name: string, value: any): XmlNode => ({ name, attrs: value.$ || {}, children: Object.entries(value).filter(([key]) => key !== '$' && key !== '_').flatMap(([key, vals]) => (vals as any[]).map(v => convert(key, v))) });
      if (!xml.manifest) throw new Error('Missing manifest root');
      root = convert('manifest', xml.manifest);
    }
    if (root.name !== 'manifest' || !/^[\w.]+$/.test(root.attrs.package || '')) throw new Error('Manifest has no valid package name');
    const app = root.children.find(x => x.name === 'application'), sdk = root.children.find(x => x.name === 'uses-sdk');
    const minSdk = sdk?.attrs['android:minSdkVersion'] || defaults?.minSdk || '1', targetSdk = sdk?.attrs['android:targetSdkVersion'] || defaults?.targetSdk || minSdk;
    const fullName = (s: string) => s.startsWith('.') ? root.attrs.package + s : s.includes('.') ? s : `${root.attrs.package}.${s}`;
    return {
      packageName: root.attrs.package, versionCode: root.attrs['android:versionCode'] || '', versionName: root.attrs['android:versionName'] || '', split: root.attrs.split || '', minSdk, targetSdk,
      permissions: [...new Set(root.children.filter(x => ['uses-permission', 'uses-permission-sdk-23'].includes(x.name)).map(x => x.attrs['android:name']).filter(Boolean))].sort(),
      components: (app?.children || []).filter(x => ['activity', 'activity-alias', 'service', 'receiver', 'provider'].includes(x.name)).map(x => {
        const explicit = x.attrs['android:exported'];
        const implicit = x.name === 'provider' ? Number(targetSdk) < 17 : x.children.some(c => c.name === 'intent-filter');
        return { type: x.name, name: fullName(x.attrs['android:name'] || '(unnamed)'), exported: explicit ? explicit === 'true' : implicit, exportReason: explicit ? 'explicit manifest attribute' : 'Android manifest default', permission: x.attrs['android:permission'] ?? app?.attrs['android:permission'] ?? defaults?.applicationPermission ?? '' };
      }),
      debuggable: app?.attrs['android:debuggable'] !== undefined ? app.attrs['android:debuggable'] === 'true' : defaults?.debuggable ?? false, allowBackup: app?.attrs['android:allowBackup'] !== undefined ? app.attrs['android:allowBackup'] !== 'false' : defaults?.allowBackup ?? true,
      usesCleartextTraffic: app?.attrs['android:usesCleartextTraffic'] ? app.attrs['android:usesCleartextTraffic'] === 'true' : defaults?.usesCleartextTraffic ?? Number(targetSdk) < 28,
      networkSecurityConfig: app?.attrs['android:networkSecurityConfig'] ?? defaults?.networkSecurityConfig ?? '',
      applicationPermission: app?.attrs['android:permission'] ?? defaults?.applicationPermission ?? '',
    };
  }
}
