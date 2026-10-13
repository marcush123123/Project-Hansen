# Validation results

## Hansen 1.1 comparison validation, October 12, 2026

TypeScript validation, the production main/preload/worker/CLI bundles, and the Vite renderer build pass for version 1.1.0. The service suite passes **28 tests**, including the prior malware and archive coverage plus deep-link/provider manifest parsing, deterministic release comparison, signer-change warnings, permission explanations, and SARIF artifact/finding mapping.

The Electron production smoke test passes under Xvfb with its existing test-only `--no-sandbox` override. It validates the About splash, settings, APK and XAPK reports, PDF cancellation/export, the release-comparison workspace, Shift-range history selection, persistent bulk labels, bulk deletion, history reload and restart, cancellation followed by another scan, real-package analysis, PDF generation, and absence of renderer exceptions. The supplied TikTok APK completed in approximately 41 seconds during this run.

Signing-certificate identity extraction, comparison JSON/PDF generation, individual JSON/SARIF report export, history filtering/deletion, and the standalone CLI compile successfully. Cryptographic signature verification, certificate proof-of-rotation validation, compiled network-security resource resolution, and live provider integrations remain outside the 1.1 verification claim.

## Malware reputation validation, October 11, 2026

Host: Linux x64. TypeScript checks, production bundling and Linux AppImage packaging passed. The service suite passed **23 tests**, including local rule combinations, negative controls, distinct XAPK hashes, snapshot integrity when a source changes, changed-file upload rejection, multipart bytes, upload destination/size restrictions, invalid responses, authorization/quota failures, pending scans, stale results, preservation of prior detections, and report escaping.

The supplied APKs were scanned locally under neutral filenames to verify content-based findings. Android code was never installed or executed, and no file or hash was sent to VirusTotal during these tests.

| Sample | SHA-256 | Local result |
| --- | --- | --- |
| DoubleLockerRansomware.apk | `79e602a062d05fbb1409afc16e6d41ac0645576b2b5c1899dc93e6852c30a71f` | Potentially malicious: ransomware-like device takeover and persistent overlay capabilities |
| vi4a.apk | `b0ff5690c31f160808a869a14fa55f9e38c82de81cf98b895badc88c997ee45c` | Potentially malicious: persistent overlay capabilities |

The packaged Linux executable passed the desktop reputation test using isolated settings and mocked VirusTotal responses. Verified flows include no network calls while disabled, API key persistence without plaintext storage, hash lookup, provider-attributed warning in the viewer and history, PDF export, cancellation without upload, confirmed upload of the exact reviewed bytes, pending analysis refresh, report reload, and automatic hash lookup without automatic upload. Both supplied APKs also produced the local warning and a PDF from the packaged application.

Artifacts: `output/malware-samples/` contains local JSON/HTML reports; `output/DoubleLockerRansomware.apk-malware-report.pdf` and `output/vi4a.apk-malware-report.pdf` contain the desktop exports. `output/reputation-report.pdf` contains **simulated** VirusTotal evidence from a harmless fixture, not a live engine verdict.

Commands: `npm test`, `npm run test:malware-samples`, `npm run build`, and `scripts/reputation-electron-test.cjs` against the packaged executable. GUI automation used Xvfb and the test-only sandbox override, as in the earlier validation. A live VirusTotal account/API key was not supplied: live lookup, vendor accuracy, real upload processing, and live large-file submission remain unverified. The large-file URL rejection and size limits were tested with mocked responses. No claim of malware detection accuracy is made from these two samples.

Current AppImage: `build/Hansen-1.0.0.AppImage`, 125,383,691 bytes, SHA-256 `e9dd5a45b7a9132104fd26d97573df57e62ababa7dc46a1cc57885ad4a9052e2`.

## Earlier baseline

The remaining sections record October 7, 2026 validation on Linux x64, before malware reputation integration.

## Final source and compilation

- TypeScript validation: passed.
- Main, worker and preload bundling: passed. Build metadata validates that external imports are Electron/Node built-ins; runtime libraries are bundled.
- Vite production renderer: passed.
- Service regression suite: **26 tests passed**, covering binary XML UTF-8/UTF-16, text manifests, export defaults, malformed input, APK scans/redaction, XAPK merging and rejection, archive defenses, HTML escaping, malware assessment, reputation handling, chunk-boundary scanning, cleanup, split inheritance, comparisons, permissions, and SARIF export.
- Electron **44.7.0**, Vite **8.3.3**, electron-builder **26.15.3**. Node 24 used for validation.
- `npm run build`: passed in the normal filesystem sandbox using local dependencies. The packaged main/worker/preload/renderer files were verified byte-for-byte against their compiled outputs.
- Linux AppImage and unpacked application built under `build/`. Packaging uses the installed Electron distribution and compiled bundles, with no production `node_modules` tree.

## Supplied real APK

Only one APK was present in the supplied directory; no real XAPK was provided. XAPK coverage uses generated base/split fixtures.

File: `../TikTok+-+Videos,+Shop+&+LIVE_47.1.4_APKPure.apk`

| Measurement | Result |
| --- | --- |
| Input bytes | 472,239,331 |
| SHA-256 | `4226ed5d3031b68208c29f62d80ac421b281fc74201bc4163d98e442d0991a40` |
| Package | `com.zhiliaoapp.musically` |
| Version | `47.1.4` |
| Manifest permissions | 64 |
| Manifest components | 650 total; 67 exported |
| DEX files / native libraries | 56 / 591 |
| Inspected files | 19,725 |
| Inspected bytes | 1,021,792,989 |
| Files excluded by type | 6,909 |
| Matched telemetry namespaces | 6 |
| Retained network origins | 250; truncation explicitly reported |
| Finding categories | 8 |
| Final-source local analysis | Passed; approximately 50 seconds |

Outputs: `output/sample-report.json` and `output/sample-report.html`. The original APK was not installed or executed. Indicator counts are not confirmed malicious behaviors.

## Desktop integration

Production Electron and the packaged Linux executable both passed these workflows in isolated temporary user-data directories:

1. Production window loaded its renderer from disk without Vite.
2. Settings were saved and read back.
3. APK selected through the picker produced the embedded report.
4. PDF save-dialog cancellation preserved the report; retry produced a real PDF.
5. XAPK drag/drop resolved the actual local file through Electron's preload bridge and produced a combined split report.
6. History reopened after renderer reload and after a complete application restart.
7. Cancelling the worker allowed another analysis to start.
8. The supplied TikTok APK produced an embedded report and an **18-page PDF**.
9. Report identity/version assertions passed and no renderer exceptions were observed.

The packaged desktop run completed before the final split-inheritance regression fix, normalized archive-duplicate check, report wording clarification and packaging dependency cleanup. Those final changes passed service tests, real-APK local analysis and compilation/package validation. The final rebuilt artifact was not given another live desktop run because the approval service became unavailable. Do not interpret the earlier desktop run as an exact final-artifact UI test.

Desktop automation used the test-only `--no-sandbox` option because this execution environment restricts Chromium's sandbox. Production configuration retains sandboxing. Normal desktop launch with the operating system's sandbox configuration was not independently validated here.

## PDF inspection

The exported sample is `output/tiktok-hansen-report.pdf` (18 A4 pages). It was rendered with system Poppler and reviewed across all pages for pagination, table wrapping and complete report sections. The PDF includes findings, permissions, exported components, origin inventory, limitations and scoring rules. It reflects the successful packaged desktop run described above. Cancelling export did not delete report history.

## Not verified

Windows/macOS packaging, signing/notarization, Android execution, signature verification, OBB behavior and malware detection accuracy. The scanner's static scope and caps are described in each report and in the README.

## Earlier AppImage identity

Size: 125,350,855 bytes. SHA-256: `fc53462d14b444850840d7ac1ad87b413d48e4c6312f9404d6e507de491fea46`.
