import { createHash, X509Certificate } from 'crypto';
import { promises as fs } from 'fs';
import AdmZip from 'adm-zip';
import { PackageSignature, SigningCertificate } from '../types';

const IDS: Record<number, string> = { 0x7109871a: 'APK Signature Scheme v2', 0xf05368c0: 'APK Signature Scheme v3', 0x1b93ad61: 'APK Signature Scheme v3.1' };
const sha256 = (data: Buffer) => createHash('sha256').update(data).digest('hex');
const u32 = (b: Buffer, p: number) => { if (p < 0 || p + 4 > b.length) throw new Error('Truncated signing block'); return b.readUInt32LE(p); };
const slice32 = (b: Buffer, p: number): [Buffer, number] => { const n = u32(b, p), end = p + 4 + n; if (end > b.length) throw new Error('Truncated signing record'); return [b.subarray(p + 4, end), end]; };

function signingBlock(apk: Buffer): { schemes: string[]; certificates: Buffer[]; block?: Buffer } {
  const min = Math.max(0, apk.length - 65557); let eocd = -1;
  for (let p = apk.length - 22; p >= min; p--) if (apk.readUInt32LE(p) === 0x06054b50) { eocd = p; break; }
  if (eocd < 0) return { schemes: [], certificates: [] };
  const central = u32(apk, eocd + 16);
  if (central < 24 || central > apk.length) return { schemes: [], certificates: [] };
  const footer = apk.subarray(central - 24, central);
  if (footer.subarray(8).toString('ascii') !== 'APK Sig Block 42') return { schemes: [], certificates: [] };
  const size = Number(footer.readBigUInt64LE(0)), start = central - size - 8;
  if (!Number.isSafeInteger(size) || start < 0 || start + 8 > central) return { schemes: [], certificates: [] };
  const block = apk.subarray(start, central), schemes: string[] = [], certificates: Buffer[] = [];
  let p = 8, end = block.length - 24;
  while (p < end) {
    if (p + 8 > end) break;
    const len = Number(block.readBigUInt64LE(p)); p += 8;
    if (!Number.isSafeInteger(len) || len < 4 || p + len > end) break;
    const id = block.readUInt32LE(p), value = block.subarray(p + 4, p + len); p += len;
    if (!IDS[id]) continue;
    schemes.push(IDS[id]);
    try {
      const [signers] = slice32(value, 0); let sp = 0;
      while (sp < signers.length) {
        const [signer, nextSigner] = slice32(signers, sp); sp = nextSigner;
        const [signedData] = slice32(signer, 0), [, certPos] = slice32(signedData, 0), [certList] = slice32(signedData, certPos); let cp = 0;
        while (cp < certList.length) { const [cert, nextCert] = slice32(certList, cp); certificates.push(cert); cp = nextCert; }
      }
    } catch { /* Preserve scheme detection when a future signer record cannot be decoded. */ }
  }
  return { schemes: [...new Set(schemes)], certificates, block };
}

export class SignatureService {
  static async inspect(file: string): Promise<PackageSignature> {
    const bytes = await fs.readFile(file), modern = signingBlock(bytes), zip = new AdmZip(bytes);
    const v1 = zip.getEntries().filter(e => !e.isDirectory && /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.entryName));
    const schemes = [...modern.schemes, ...(v1.length ? ['JAR signing (v1)'] : [])], certMap = new Map<string, SigningCertificate>();
    for (const der of modern.certificates) {
      const fingerprint = sha256(der);
      try {
        const cert = new X509Certificate(der);
        certMap.set(fingerprint, { sha256: fingerprint, subject: cert.subject, issuer: cert.issuer, serialNumber: cert.serialNumber, validFrom: cert.validFrom, validTo: cert.validTo, publicKeyAlgorithm: cert.publicKey.asymmetricKeyType });
      } catch { certMap.set(fingerprint, { sha256: fingerprint }); }
    }
    const artifacts = v1.map(e => e.getData()), artifactSha256 = artifacts.length || modern.block ? sha256(Buffer.concat([...(modern.block ? [modern.block] : []), ...artifacts])) : undefined;
    if (!schemes.length) return { status: 'unsigned', schemes: [], certificates: [], detail: 'No APK signing block or JAR signature artifact was detected.' };
    if (!certMap.size) return { status: 'unverified', schemes, certificates: [], artifactSha256, detail: 'Signature artifacts were detected, but Hansen could not extract a stable signing certificate identity.' };
    return { status: 'signed', schemes, certificates: [...certMap.values()], artifactSha256, detail: 'Signing certificate identity was extracted locally. Cryptographic signature validity is not yet independently verified by Hansen.' };
  }
}
