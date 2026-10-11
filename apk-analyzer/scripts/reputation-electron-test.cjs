const { _electron: electron } = require('playwright');
const { buildSync } = require('esbuild');
const fs = require('fs/promises');
const { join, resolve } = require('path');
const os = require('os');
const assert = require('assert/strict');
(async () => {
  await fs.mkdir('output', { recursive: true });
  buildSync({ entryPoints: ['tests/fixtures.ts'], outfile: 'output/fixtures.cjs', bundle: true, platform: 'node', format: 'cjs' });
  const { writeApk } = require('../output/fixtures.cjs');
  const tmp = await fs.mkdtemp(join(os.tmpdir(), 'hansen-vt-ui-'));
  const fixture = join(tmp, 'fixture.apk'); writeApk(fixture);
  const env = { ...process.env, XDG_CONFIG_HOME: join(tmp, 'config') }; delete env.ELECTRON_RUN_AS_NODE;
  const args = process.env.HANSEN_EXECUTABLE ? [] : [resolve('.')]; if (process.env.HANSEN_TEST_NO_SANDBOX === '1') args.unshift('--no-sandbox');
  let app;
  try {
    app = await electron.launch({ executablePath: process.env.HANSEN_EXECUTABLE || require('electron'), args, env, timeout: 30000 });
    const page = await app.firstWindow(); page.setDefaultTimeout(90000);
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.getByRole('heading', { name: 'Understand what you install.' }).waitFor();
    const userData = await app.evaluate(({ app }) => app.getPath('userData')); assert.ok(userData.startsWith(tmp));
    // Fake transport lives only in this isolated test process. No public API or APK upload occurs.
    await app.evaluate(() => {
      globalThis.vtCalls = []; globalThis.vtHash = ''; globalThis.vtPosts = 0;
      globalThis.fetch = async (url, init = {}) => {
        const address = String(url); if (!address.startsWith('https://www.virustotal.com/api/v3/')) throw new Error('Unexpected test URL');
        globalThis.vtCalls.push(address);
        if (init.method === 'POST') {
          globalThis.vtPosts++; const blob = init.body.get('file');
          globalThis.vtUploadedBytes = Array.from(new Uint8Array(await blob.arrayBuffer()));
          return new Response(JSON.stringify({ data: { type: 'analysis', id: 'ui-analysis' } }));
        }
        if (address.includes('/analyses/')) return new Response(JSON.stringify({ data: { type: 'analysis', id: 'ui-analysis', attributes: { status: 'completed' } } }));
        const hash = address.split('/').pop(); globalThis.vtHash = hash;
        return new Response(JSON.stringify({ data: { type: 'file', id: hash, attributes: { sha256: hash, last_analysis_date: Math.floor(Date.now()/1000), last_analysis_stats: { malicious: 3, suspicious: 0, harmless: 0, undetected: 1, timeout: 0, 'confirmed-timeout': 0, failure: 0, 'type-unsupported': 0 }, last_analysis_results: { A: { category: 'malicious', result: 'Test.Trojan' }, B: { category: 'malicious', result: 'Test.Trojan' }, C: { category: 'malicious', result: 'Test.Trojan' }, D: { category: 'undetected', result: null } } } } }));
      };
    });
    await app.evaluate(({ dialog }, file) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [file] }); }, fixture);
    await page.getByRole('button', { name: /Browse packages/ }).click();
    await page.getByRole('heading', { name: 'Malware assessment incomplete', exact: true }).waitFor();
    assert.equal(await app.evaluate(() => globalThis.vtCalls.length), 0);
    console.log('Offline report makes no VirusTotal requests');
    await page.getByRole('button', { name: /Analysis settings/ }).click();
    await page.getByLabel('Hash lookups').selectOption('enabled');
    await page.getByLabel('VirusTotal API key').fill('ui-mock-key');
    await page.getByRole('button', { name: 'Save settings' }).click();
    await page.getByText('Settings saved. They apply to your next analysis.').waitFor();
    const config = await fs.readFile(join(userData, 'config.json'), 'utf8'); assert.ok(!config.includes('ui-mock-key'));
    await page.getByRole('button', { name: /Package inspector/ }).click();
    await page.getByText('VirusTotal evidence and actions', { exact: true }).click();
    await page.getByRole('button', { name: 'Check hash', exact: true }).click();
    await page.getByRole('heading', { name: 'Flagged malicious by VirusTotal', exact: true }).waitFor();
    const summary = (await page.evaluate(() => window.api.listReports()))[0]; assert.equal(summary.malwareVerdict, 'flagged-malicious');
    await page.frameLocator('iframe').getByRole('heading', { name: 'Flagged malicious by VirusTotal', exact: true }).waitFor();
    console.log('Lookup warning and history verified');
    const pdf = resolve('output/reputation-report.pdf');
    await app.evaluate(({ dialog }, file) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: file }); }, pdf);
    await page.getByRole('button', { name: /Export PDF/ }).click(); await page.getByText(/PDF saved to/).waitFor();
    assert.ok((await fs.readFile(pdf)).subarray(0,5).equals(Buffer.from('%PDF-')));
    await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 0 }); });
    await page.getByRole('button', { name: 'Upload APK…', exact: true }).click();
    await page.getByRole('button', { name: 'Upload APK…', exact: true }).waitFor();
    await page.waitForFunction(() => !document.querySelector('button')?.disabled && !Array.from(document.querySelectorAll('button')).some(b => b.textContent === 'Cancel request'));
    assert.equal(await app.evaluate(() => globalThis.vtPosts), 0);
    console.log('Upload cancellation sends no bytes');
    await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1 }); });
    await page.getByRole('button', { name: 'Upload APK…', exact: true }).click();
    await page.waitForFunction(() => !Array.from(document.querySelectorAll('button')).some(b => b.textContent === 'Cancel request'));
    assert.equal(await page.getByRole('button', { name: 'Check status', exact: true }).count(), 1, await page.locator('.report-view').innerText());
    assert.equal(await app.evaluate(() => globalThis.vtPosts), 1);
    assert.deepEqual(Buffer.from(await app.evaluate(() => globalThis.vtUploadedBytes)), await fs.readFile(fixture));
    console.log('Confirmed upload uses exact reviewed bytes');
    await page.getByRole('button', { name: 'Check status', exact: true }).click();
    await page.getByRole('button', { name: 'Check hash', exact: true }).waitFor();
    assert.equal((await page.evaluate(id => window.api.getReport(id), summary.id)).reputation[0].status, 'completed');
    await page.reload(); await page.locator('.history-item').first().click();
    await page.getByRole('heading', { name: 'Flagged malicious by VirusTotal', exact: true }).waitFor();
    await page.getByRole('button', { name: 'New analysis', exact: true }).click();
    await page.getByRole('button', { name: /Browse packages/ }).click();
    await page.getByRole('heading', { name: 'Flagged malicious by VirusTotal', exact: true }).waitFor();
    assert.equal(await app.evaluate(() => globalThis.vtPosts), 1);
    console.log('Automatic hash lookup verified without automatic upload');
    await page.getByRole('button', { name: /Analysis settings/ }).click();
    await page.getByLabel('Hash lookups').selectOption('disabled');
    await page.getByRole('button', { name: 'Save settings' }).click();
    await page.getByText('Settings saved. They apply to your next analysis.').waitFor();
    await page.getByRole('button', { name: /Package inspector/ }).click();
    for (const name of ['DoubleLockerRansomware.apk', 'vi4a.apk']) {
      const sample = resolve('..', name);
      try { await fs.access(sample); } catch { console.log(`Optional local sample unavailable: ${name}`); continue; }
      await page.getByRole('button', { name: 'New analysis', exact: true }).click();
      await app.evaluate(({ dialog }, file) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [file] }); }, sample);
      await page.getByRole('button', { name: /Browse packages/ }).click();
      await page.getByRole('heading', { name: 'Potentially malicious', exact: true }).waitFor();
      await page.frameLocator('iframe').getByRole('heading', { name: 'Potentially malicious', exact: true }).waitFor();
      const samplePdf = resolve(`output/${name}-malware-report.pdf`);
      await app.evaluate(({ dialog }, file) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: file }); }, samplePdf);
      await page.getByRole('button', { name: /Export PDF/ }).click(); await page.getByText(/PDF saved to/).waitFor();
      assert.ok((await fs.readFile(samplePdf)).subarray(0,5).equals(Buffer.from('%PDF-')));
      console.log(`${name}: desktop malware warning and PDF export passed; no remote submission`);
    }
    assert.deepEqual(errors, []);
    console.log('VirusTotal desktop flow passed: no automatic uploads, encrypted/session-only key, lookup, PDF, cancel/confirm upload, pending refresh and persisted verdict. All remote responses were mocked.');
  } finally { if (app) await app.close(); await fs.rm(tmp, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
