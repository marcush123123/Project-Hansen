# Validation results

Date: October 7, 2026 (America/Los_Angeles). Host: Linux x64.

## Final source and compilation

- TypeScript validation: passed.
- Main, worker and preload bundling: passed. Build metadata validates that external imports are Electron/Node built-ins; runtime libraries are bundled.
- Vite production renderer: passed.
- Service regression suite: **12 tests passed**, covering binary XML UTF-8/UTF-16, text manifests, export defaults, malformed input, APK scans/redaction, XAPK merging and rejection, archive defenses, HTML escaping, AI response validation/failure fallback, chunk-boundary scanning, cleanup, and split inheritance.
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

Live Ollama or cloud inference (no service credentials supplied), Windows/macOS packaging, signing/notarization, Android execution, signature verification, OBB behavior and malware detection accuracy. The scanner's static scope and caps are described in each report and in the README.

## Final AppImage identity

Size: 125,350,855 bytes. SHA-256: `fc53462d14b444850840d7ac1ad87b413d48e4c6312f9404d6e507de491fea46`.
