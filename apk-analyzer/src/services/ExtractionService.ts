import AdmZip from 'adm-zip';
import path from 'path';
import { promises as fs } from 'fs';
import { createHash } from 'crypto';
export const LIMITS = { archiveBytes: 2 * 1024 ** 3, expandedBytes: 3 * 1024 ** 3, entryBytes: 256 * 1024 ** 2, entries: 100000, packages: 100 };
export const isSearchable = (name: string) => /\.(dex|so|arsc|xml|json|js|html|txt|properties|java|kt|smali|conf|cfg)$/i.test(name);
export interface ExtractedPackage { fileName: string; dir: string; sourcePath: string; entries: number; dexFiles: number; nativeLibraries: number; skippedFiles: number; sha256?: string; }
export class ExtractionService {
  static validateEntries(zip: AdmZip, maxEntry = LIMITS.entryBytes) {
    const entries = zip.getEntries();
    if (entries.length > LIMITS.entries) throw new Error('Archive exceeds 100,000 entries');
    const names = new Set<string>(), foldedNames = new Set<string>(), caseCollisions = new Set<string>(); let total = 0;
    for (const entry of entries) {
      const name = entry.entryName;
      if (!name || name.includes('\\') || name.includes('\0') || name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..')) throw new Error('Unsafe archive entry path');
      const key = path.posix.normalize(name).replace(/\/+$/, '');
      if (names.has(key)) throw new Error('The package contains the same archive path more than once. Hansen cannot determine which copy is authoritative, so the package was not extracted.');
      names.add(key);
      const foldedKey = key.toLowerCase();
      if (foldedNames.has(foldedKey)) caseCollisions.add(foldedKey);
      foldedNames.add(foldedKey);
      if (((entry.header.attr >>> 16) & 0xf000) === 0xa000) throw new Error('Archive symlinks are not supported');
      if (entry.header.flags & 1) throw new Error('Encrypted archives are not supported');
      if (entry.header.size > maxEntry) throw new Error(`Archive entry exceeds size limit: ${name}`);
      total += entry.header.size;
      if (total > LIMITS.expandedBytes) throw new Error('Archive expands beyond the 3 GiB safety limit');
    }
    return { entries, total, caseCollisions: caseCollisions.size };
  }
  static async extract(input: string, tempDir: string): Promise<{ packages: ExtractedPackage[]; warnings: string[] }> {
    const stat = await fs.stat(input);
    if (!stat.isFile() || stat.size > LIMITS.archiveBytes) throw new Error('Choose an APK or XAPK file no larger than 2 GiB');
    if (!/\.(apk|xapk)$/i.test(input)) throw new Error('Unsupported file type. Choose .apk or .xapk');
    const warnings: string[] = [], packages: ExtractedPackage[] = [];
    let expanded = 0;
    const unpackApk = async (zip: AdmZip, fileName: string, sha256?: string, sourcePath?: string, sourceBytes?: Buffer) => {
      const { entries, total, caseCollisions } = this.validateEntries(zip);
      expanded += total;
      if (expanded > LIMITS.expandedBytes) throw new Error('Combined APK contents exceed 3 GiB');
      if (!entries.some(e => e.entryName === 'AndroidManifest.xml')) throw new Error(`${fileName}: missing AndroidManifest.xml`);
      const dir = path.join(tempDir, `package-${packages.length}`);
      await fs.mkdir(dir, { recursive: true });
      let skippedFiles = 0;
      for (const [index, entry] of entries.entries()) {
        if (entry.isDirectory) continue;
        if (!isSearchable(entry.entryName)) { skippedFiles++; continue; }
        // Keep the manifest at its expected location. Every other scanned entry gets
        // a unique internal name so case-only resource names remain safe on Windows.
        const extension = path.posix.extname(entry.entryName).toLowerCase();
        const out = entry.entryName === 'AndroidManifest.xml' ? path.join(dir, entry.entryName) : path.join(dir, 'content', `${index.toString().padStart(6, '0')}${extension}`);
        await fs.mkdir(path.dirname(out), { recursive: true });
        const data = entry.getData();
        if (data.length !== entry.header.size) throw new Error('Archive entry size mismatch');
        await fs.writeFile(out, data);
      }
      if (caseCollisions) warnings.push(`${fileName} contains ${caseCollisions} archive path collision${caseCollisions === 1 ? '' : 's'} that differ only by letter case. Hansen isolated these entries so they can be scanned safely on this operating system.`);
      const packageSource = sourcePath || path.join(tempDir, `source-${packages.length}.apk`);
      if (!sourcePath) await fs.writeFile(packageSource, sourceBytes!, { mode: 0o600 });
      packages.push({ fileName, dir, sourcePath: packageSource, sha256, entries: entries.length, dexFiles: entries.filter(e => /\.dex$/i.test(e.entryName)).length, nativeLibraries: entries.filter(e => /\.so$/i.test(e.entryName)).length, skippedFiles });
    };
    const zip = new AdmZip(input);
    if (/\.xapk$/i.test(input)) {
      const { entries } = this.validateEntries(zip, LIMITS.archiveBytes);
      const apks = entries.filter(e => !e.isDirectory && /\.apk$/i.test(e.entryName));
      if (!apks.length) throw new Error('XAPK contains no APK packages');
      if (apks.length > LIMITS.packages) throw new Error('XAPK exceeds 100 APK packages');
      for (const entry of apks) {
        const bytes = entry.getData();
        await unpackApk(new AdmZip(bytes), entry.entryName, createHash('sha256').update(bytes).digest('hex'), undefined, bytes);
      }
      if (entries.some(e => /\.obb$/i.test(e.entryName))) warnings.push('OBB expansion data is inventoried by the container but is not scanned.');
      warnings.push('XAPK APK entries are analyzed independently and merged; manifest.json is not trusted as package identity.');
    } else await unpackApk(zip, path.basename(input), undefined, input);
    return { packages, warnings };
  }
  static async cleanup(tempDir: string) { await fs.rm(tempDir, { recursive: true, force: true }); }
}
