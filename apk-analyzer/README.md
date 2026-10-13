# Hansen

Hansen is a desktop application for static inspection of Android APK and XAPK packages. Reports are available in the application and can be exported as PDF.

Version 1.1 adds change-aware review: compare two saved releases, inspect signing-certificate continuity, and export comparison evidence as JSON or PDF. Reports also include deeper component intent surfaces, explainable permissions, structured tracker context, JSON/SARIF export, searchable history, and explicit deletion. See the [1.1 feature program](V1_1_FEATURES.md).

## Build

Requires Node.js 22.12 or later and npm 10 or later. The repository selects Node.js 24 through `.nvmrc`. If your terminal uses an older version, follow the [Node.js setup instructions](LAUNCH_GUIDE.md#nodejs-setup) before installing dependencies.

```bash
npm ci --include=optional
npm run build
npm start
```

Run `npm run dev` to develop the renderer. Report interpretation is always performed locally; application settings only control optional VirusTotal reputation lookups.

Run a local headless scan without Electron:

```bash
npm run analyze -- app.apk --format sarif --output app-hansen.sarif
```

## Malware assessment

Local capability combinations can flag potentially malicious APKs. Enable VirusTotal hash lookups and enter an API key in Analysis settings to add engine verdicts for exact APK hashes. XAPK entries are checked individually, with four automatic checks per analysis and manual checks for the remainder. Missing, stale, failed or pending checks remain incomplete. The malware assessment appears before the separate configuration grade in the application and PDF, and is included in history.

Use Upload APK from the report to submit a file after selecting and verifying the original package and confirming VirusTotal's data sharing implications. Uploads are never automatic. Use Check status for pending submissions. See the repository [malware assessment documentation](../README.md#malware-assessment-and-virustotal) for verdict thresholds, coverage limits and account requirements.

## Documentation

Read [Getting Started](GETTING_STARTED.md), [Architecture](ARCHITECTURE.md), and [Launch Guide](LAUNCH_GUIDE.md). [Validation Results](TEST_RESULTS.md) records the tested APK and build details.

## Scope

The report combines manifest data, bounded static string matches and optional VirusTotal evidence. It does not execute Android code or certify that a package is safe. See each report for its scan coverage, dated engine results and limitations.

## License

Apache License 2.0. See the repository [LICENSE](../LICENSE).
