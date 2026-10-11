import AdmZip from 'adm-zip';
export function binaryManifest(utf8 = true): Buffer {
  const strings = ['manifest', 'package', 'com.example.binary', 'http://schemas.android.com/apk/res/android', 'versionCode', 'versionName', '1.2', 'uses-sdk', 'minSdkVersion', 'targetSdkVersion', 'uses-permission', 'name', 'android.permission.CAMERA', 'application', 'debuggable', 'activity', '.Main', 'exported'];
  const encoded = strings.map(s => {
    const b = Buffer.from(s, utf8 ? 'utf8' : 'utf16le');
    if (utf8) return Buffer.concat([Buffer.from([s.length, b.length]), b, Buffer.from([0])]);
    const len = Buffer.alloc(2); len.writeUInt16LE(s.length); return Buffer.concat([len,b,Buffer.alloc(2)]);
  });
  const offsets = Buffer.alloc(strings.length * 4); let offset = 0;
  encoded.forEach((b,i) => { offsets.writeUInt32LE(offset,i*4); offset+=b.length; });
  const pool = Buffer.alloc(28); pool.writeUInt16LE(1,0); pool.writeUInt16LE(28,2); pool.writeUInt32LE(28+offsets.length+offset,4); pool.writeUInt32LE(strings.length,8); pool.writeUInt32LE(utf8?256:0,16); pool.writeUInt32LE(28+offsets.length,20);
  const idx = (s: string) => strings.indexOf(s);
  const start = (name: string, attrs: [string, string | number | boolean, boolean?][]) => {
    const b = Buffer.alloc(36+attrs.length*20); b.writeUInt16LE(0x102,0); b.writeUInt16LE(16,2); b.writeUInt32LE(b.length,4); b.writeUInt32LE(0xffffffff,16); b.writeUInt32LE(idx(name),20); b.writeUInt16LE(20,24); b.writeUInt16LE(20,26); b.writeUInt16LE(attrs.length,28);
    attrs.forEach(([key,v,ns],i) => { const p=36+i*20; b.writeUInt32LE(ns?3:0xffffffff,p); b.writeUInt32LE(idx(key),p+4); b.writeUInt32LE(0xffffffff,p+8); b.writeUInt16LE(8,p+12); b[p+15]=typeof v==='string'?3:typeof v==='boolean'?0x12:0x10; b.writeUInt32LE(typeof v==='string'?idx(v):Number(v),p+16); }); return b;
  };
  const end = (name:string) => { const b=Buffer.alloc(24);b.writeUInt16LE(0x103,0);b.writeUInt16LE(16,2);b.writeUInt32LE(24,4);b.writeUInt32LE(0xffffffff,16);b.writeUInt32LE(idx(name),20);return b; };
  const chunks = Buffer.concat([pool,offsets,...encoded,start('manifest',[['package','com.example.binary'],['versionCode',12,true],['versionName','1.2',true]]),start('uses-sdk',[['minSdkVersion',23,true],['targetSdkVersion',34,true]]),end('uses-sdk'),start('uses-permission',[['name','android.permission.CAMERA',true]]),end('uses-permission'),start('application',[['debuggable',true,true]]),start('activity',[['name','.Main',true],['exported',true,true]]),end('activity'),end('application'),end('manifest')]);
  const header=Buffer.alloc(8);header.writeUInt16LE(3);header.writeUInt16LE(8,2);header.writeUInt32LE(chunks.length+8,4);return Buffer.concat([header,chunks]);
}
export function textManifest(split = '', pkg = 'com.example.fixture'): string {
  return `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="${pkg}" android:versionCode="1" android:versionName="1.0" ${split ? `split="${split}"` : ''}><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34"/><uses-permission android:name="android.permission.CAMERA"/><application android:debuggable="true" android:allowBackup="false"><activity android:name=".Main" android:exported="true"/><service android:name=".Private" android:exported="false"/><receiver android:name="Receiver"><intent-filter><action android:name="example.ACTION"/></intent-filter></receiver><provider android:name="Provider"/></application></manifest>`;
}
export function writeApk(file: string, manifest: string | Buffer = textManifest()) {
  const zip = new AdmZip(); zip.addFile('AndroidManifest.xml', Buffer.isBuffer(manifest) ? manifest : Buffer.from(manifest));
  zip.addFile('classes.dex', Buffer.from('dex\n035\0Lcom/google/firebase/analytics/FirebaseAnalytics; https://api.example.com/private?token=do-not-retain http://legacy.example.com/ java/lang/reflect DexClassLoader AKIA1234567890ABCDEF'));
  zip.addFile('assets/config.json', Buffer.from('{"url":"https://user:secret@account.example.org/path?token=secret"}'));
  zip.addFile('assets/picture.png', Buffer.from('skipped media')); zip.writeZip(file);
}
