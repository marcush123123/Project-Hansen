import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import AdmZip from 'adm-zip';
import { ManifestParser, decodeBinaryXml } from '../src/services/ManifestParser';
import { ExtractionService } from '../src/services/ExtractionService';
import { LLMService } from '../src/services/LLMService';
import { analyzeApkWorkflow } from '../src/main/apkAnalyzer';
import { ReportGenerator } from '../src/services/ReportGenerator';
import { binaryManifest, textManifest, writeApk } from './fixtures';
const settings = { provider: 'offline' as const, modelName: '', temperature: 0.2 };
const temp = () => fs.mkdtemp(path.join(os.tmpdir(), 'hansen-test-'));
test('decodes binary Android XML string pools and typed attributes (UTF-8 and UTF-16)', async () => {
  for (const utf8 of [true,false]) {
    const m=await ManifestParser.parse(binaryManifest(utf8));
    assert.equal(m.packageName,'com.example.binary');assert.equal(m.versionCode,'12');assert.equal(m.versionName,'1.2');assert.equal(m.targetSdk,'34');assert.equal(m.debuggable,true);assert.deepEqual(m.permissions,['android.permission.CAMERA']);assert.equal(m.components[0].name,'com.example.binary.Main');assert.equal(m.components[0].exported,true);
  }
});
test('text manifest honors explicit export, intent-filter defaults and modern provider default', async () => {
  const m=await ManifestParser.parse(Buffer.from(textManifest()));
  assert.deepEqual(m.components.map(c=>c.exported),[true,false,true,false]);assert.equal(m.allowBackup,false);assert.equal(m.usesCleartextTraffic,false);
});
test('rejects malformed binary manifests and entity declarations', async () => {
  assert.throws(()=>decodeBinaryXml(binaryManifest().subarray(0,25)));
  const bad=binaryManifest();bad.writeUInt32LE(0,12);assert.throws(()=>decodeBinaryXml(bad));
  await assert.rejects(ManifestParser.parse(Buffer.from('<!DOCTYPE foo><manifest/>')),/DTD/);
  await assert.rejects(ManifestParser.parse(Buffer.from('<manifest></manifest>')),/manifest root|package name/);
});
test('APK workflow scans compiled strings, redacts credentials, renders evidence, cleans extraction', async () => {
  const dir=await temp(), file=path.join(dir,'fixture.APK'), extraction=path.join(dir,'extracted');
  try {
    writeApk(file);const r=await analyzeApkWorkflow(file,settings,extraction,()=>{});
    assert.equal(r.context.packageName,'com.example.fixture');assert.equal(r.packages[0].dexFiles,1);
    assert.ok(r.context.trackerSDKs.includes('com.google.firebase.analytics'));
    assert.ok(r.context.endpoints.includes('https://api.example.com'));assert.ok(r.context.endpoints.includes('https://account.example.org'));
    assert.deepEqual(r.context.apiKeys,['AWS access key pattern']);
    assert.ok(!JSON.stringify(r).includes('AKIA123'));assert.ok(!JSON.stringify(r).includes('do-not-retain'));
    assert.equal(r.coverage.skippedFiles,1);assert.match(r.sha256,/^[a-f0-9]{64}$/);
    const html=ReportGenerator.buildHtmlReport(r);assert.ok(html.includes('Requested permissions'));assert.ok(html.includes('Exported components'));assert.ok(html.includes('Coverage and limitations'));
    r.fileName='<img src=x onerror=alert(1)>';r.assessment.threatModel='<script>alert(1)</script>';
    const escaped=ReportGenerator.buildHtmlReport(r);assert.ok(!escaped.includes('<script>'));assert.ok(escaped.includes('&lt;img'));
    await assert.rejects(fs.stat(extraction), {code:'ENOENT'});
  } finally { await fs.rm(dir,{recursive:true,force:true}); }
});
test('merges base and split APKs from XAPK', async () => {
  const dir=await temp();try { const a=path.join(dir,'base.apk'),b=path.join(dir,'split.apk');writeApk(a);writeApk(b,textManifest('config.en'));
    const zip=new AdmZip();zip.addFile('base.apk',await fs.readFile(a));zip.addFile('nested/config.en.apk',await fs.readFile(b));zip.addFile('manifest.json',Buffer.from('{"package_name":"untrusted"}'));zip.addFile('main.obb',Buffer.from('data'));const file=path.join(dir,'fixture.XAPK');zip.writeZip(file);
    const r=await analyzeApkWorkflow(file,settings,path.join(dir,'extract'),()=>{});assert.equal(r.format,'XAPK');assert.equal(r.packages.length,2);assert.equal(r.context.packageName,'com.example.fixture');assert.equal(r.context.permissions.length,1);assert.ok(r.warnings.some(w=>w.includes('OBB')));
  } finally { await fs.rm(dir,{recursive:true,force:true}); }
});
test('rejects incomplete or mismatched XAPK sets and removes temporary files on failure', async () => {
  const dir=await temp();try { const a=path.join(dir,'base.apk'),b=path.join(dir,'other.apk');writeApk(a);writeApk(b,textManifest('config.en','com.example.other'));
    for (const includeBase of [true,false]) {const zip=new AdmZip();if(includeBase)zip.addFile('base.apk',await fs.readFile(a));zip.addFile('other.apk',await fs.readFile(b));const file=path.join(dir,'bad.xapk');zip.writeZip(file);const extraction=path.join(dir,'extract');await assert.rejects(analyzeApkWorkflow(file,settings,extraction,()=>{}),includeBase?/mismatched/:/base APK/);await assert.rejects(fs.stat(extraction),{code:'ENOENT'});}
  } finally { await fs.rm(dir,{recursive:true,force:true}); }
});
test('rejects corrupt archives, unsupported files and packages without manifests', async () => {
  const dir=await temp();try {const bad=path.join(dir,'bad.apk');await fs.writeFile(bad,'not a zip');await assert.rejects(ExtractionService.extract(bad,path.join(dir,'a')));
    const zip=new AdmZip();zip.addFile('hello.txt',Buffer.from('hi'));zip.writeZip(bad);await assert.rejects(ExtractionService.extract(bad,path.join(dir,'b')),/missing/);
    const other=path.join(dir,'bad.txt');await fs.writeFile(other,'x');await assert.rejects(ExtractionService.extract(other,path.join(dir,'c')),/Unsupported/);
  } finally {await fs.rm(dir,{recursive:true,force:true});}
});
test('rejects path traversal, symlinks, duplicate names, oversized and encrypted entries before extraction', () => {
  const entry=(name:string)=>({entryName:name,isDirectory:false,header:{size:1,attr:0,flags:0},getData:()=>Buffer.alloc(1)});
  const validate=(entries:any[])=>ExtractionService.validateEntries({getEntries:()=>entries} as any);
  for(const name of ['../evil','/absolute','C:/evil','a\\b','a/../b']) assert.throws(()=>validate([entry(name)]),/Unsafe/);
  assert.throws(()=>validate([entry('a'),entry('A')]),/Duplicate/);
  assert.throws(()=>validate([entry('a/b'),entry('a/./b')]),/Duplicate/);
  const symlink=entry('link');symlink.header.attr=0xa000<<16;assert.throws(()=>validate([symlink]),/symlink/);
  const huge=entry('huge');huge.header.size=300*1024**2;assert.throws(()=>validate([huge]),/size limit/);
  const encrypted=entry('encrypted');encrypted.header.flags=1;assert.throws(()=>validate([encrypted]),/Encrypted/);
});
test('AI validates schema, preserves zero scores and rejects fabricated fallbacks', () => {
  const llm=new LLMService({...settings,provider:'ollama'});const parse=(s:string)=>(llm as any).parseAnalysisResponse(s);
  const valid={grade:'F',safetyScore:0,transparencyScore:0,telemetrySummary:'Unknown',threatModel:'Uncertain'};assert.equal(parse(JSON.stringify(valid)).safetyScore,0);
  assert.throws(()=>parse('{}'));assert.throws(()=>parse(JSON.stringify({...valid,safetyScore:101})));assert.throws(()=>parse('no json'));
});
test('AI failure preserves local report and records a warning', async () => {
  const dir=await temp(), original=LLMService.prototype.analyzeApk;
  try {
    const file=path.join(dir,'fixture.apk');writeApk(file);
    LLMService.prototype.analyzeApk=async()=>{throw new Error('simulated unavailable provider');};
    const report=await analyzeApkWorkflow(file,{...settings,provider:'ollama'},path.join(dir,'extract'),()=>{});
    assert.ok(report.findings.length>0);assert.equal(report.ai,undefined);assert.ok(report.warnings.some(w=>w.includes('AI interpretation was unavailable')));
  } finally {LLMService.prototype.analyzeApk=original;await fs.rm(dir,{recursive:true,force:true});}
});
test('chunked scanning detects split-boundary ASCII strings and UTF-16 resource strings', async () => {
  const { StaticAnalyzer } = await import('../src/services/StaticAnalyzer');
  const dir=await temp();try {
    const bytes=Buffer.concat([Buffer.alloc(1024*1024-8,0),Buffer.from('https://boundary.example.org/path?secret=hidden\0'),Buffer.from('com.adjust https://wide.example.org/','utf16le')]);
    await fs.writeFile(path.join(dir,'resources.arsc'),bytes);
    const result=await StaticAnalyzer.analyzeCode(dir);assert.ok(result.endpoints.includes('https://boundary.example.org'));assert.ok(result.endpoints.includes('https://wide.example.org'));assert.ok(result.trackerSDKs.includes('com.adjust'));assert.ok(!JSON.stringify(result).includes('hidden'));
  }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('split manifests inherit base SDK and application flags instead of legacy defaults', async () => {
  const base=await ManifestParser.parse(Buffer.from(textManifest()));
  const split=await ManifestParser.parse(Buffer.from('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.fixture" split="config.en" android:versionCode="1"><application><provider android:name=".SplitProvider"/></application></manifest>'),base);
  assert.equal(split.targetSdk,'34');assert.equal(split.minSdk,'23');assert.equal(split.allowBackup,false);assert.equal(split.usesCleartextTraffic,false);assert.equal(split.debuggable,true);assert.equal(split.components[0].exported,false);
});
