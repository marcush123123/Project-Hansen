declare module 'adm-zip' {
  class AdmZip {
    constructor(input?: string | Buffer);
    getEntries(): Array<{ entryName: string; isDirectory: boolean; header: { size: number; compressedSize: number; flags: number; attr: number }; getData(): Buffer }>;
    addFile(name: string, data: Buffer): void;
    writeZip(path: string): void;
  }
  export default AdmZip;
}
declare module 'xml2js' { export function parseStringPromise(text: string, options?: unknown): Promise<any>; }
declare const __APP_VERSION__: string;
