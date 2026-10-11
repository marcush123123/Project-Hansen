# Architecture

## Processes and boundaries

```text
React renderer -> isolated preload -> Electron main -> analysis worker
                                           |               |
                                  settings/history     validated archive
                                           |           decoded manifests
                                  report HTML/PDF       static string scan
```

- **Renderer** (`src/renderer`): file drop/picker, settings, progress, history, and complete report viewer. It cannot import Node APIs. Analysis is initiated by a user event, not by a React mount effect.
- **Preload** (`src/preload/preload.ts`): explicitly typed IPC methods only. Progress subscriptions return an unsubscribe function.
- **Main** (`src/main/main.ts`): validates IPC origin and inputs, owns settings/history, creates at most one worker, manages timeout/cancellation, and exports PDFs through a native dialog. Production loads a local HTML file; development requires an explicit `--dev` flag.
- **Worker** (`src/main/analysisWorker.ts`): executes the workflow in `apkAnalyzer.ts`. It performs CPU/filesystem/network work away from Electron's main event loop and emits progress, report or error messages.

The main window uses sandboxing, context isolation, no Node integration, and blocks navigation/new windows. Report HTML is escaped, has a restrictive CSP, and is embedded in an iframe with an empty sandbox permission set. The hidden PDF window also disables JavaScript and Node integration. Packages are not installed, executed or evaluated.

## Analysis pipeline

1. Validate extension and file size; copy the input into a private temporary snapshot so hashes and analysis refer to identical bytes. Inspect ZIP paths, entry types/counts and expansion limits before writing selected files into a fresh temporary directory.
2. For XAPK, inspect every nested `.apk`. Require one base, consistent package/version code and unique split identifiers. Omitted split SDK and application flags inherit from the base. Container metadata cannot override decoded identity.
3. Decode Android binary XML string pools, typed attributes, element chunks and namespaces directly. Read ordinary text XML through `xml2js`; reject DTD/entity declarations. Decode permissions, SDK levels, flags and export semantics; manifest errors fail the scan instead of silently returning an empty clean result.
4. Inspect DEX, SO, resource tables and selected text files in 1 MiB chunks. Search Latin-1/UTF-16 strings for SDK namespaces, URL origins, credential patterns and code capability references. Record bounded file evidence and aggregate coverage.
5. Build structured `ContextJSON`; calculate deterministic local review findings and scores. Separate malware rules correlate capability evidence within each APK and retain the rule version and evidence. Calculate original APK hashes for each XAPK entry.
6. If enabled, send only that summary to the selected LLM. Validate its response fields and scores. Failure adds a warning while preserving local findings.
7. Return an `AnalysisReport` to main. When enabled, main checks up to four unique APK hashes through VirusTotal, with one shared rate limiter and cancellable requests. Unchecked splits remain explicitly incomplete. Compute the separate malware assessment, persist atomically, and keep the newest 20 reports. Remove extraction files in `finally`; main also removes temporary files after worker termination or error.

`VirusTotalService` uses fixed HTTPS API endpoints, prevents redirects and validates large upload destinations. Requests are spaced by 16 seconds; 429 responses extend the cooldown. File identity, statistics, engine results and dates are validated before verdict calculation. Failed refreshes retain prior positive evidence. Completed negative results older than 30 days are treated as incomplete. At least three malicious engine detections trigger a provider-attributed warning, while smaller positive counts, suspicious detections or local rules trigger a potential-malware warning. No AI output changes this result.

Upload is a separate main-process action: select the original APK/XAPK, stage and hash a snapshot, verify it against the saved report, extract only the selected APK where necessary, and request native confirmation. No automatic upload path exists. Multipart uploads above 32 MiB obtain a single-use upload URL; 650 MiB is the maximum supported size. The analysis ID is persisted for manual status refresh. Hash lookup, upload and status checks share the same rate limiter. Upload staging is removed on normal completion, cancellation or failure.

Resource bounds are implemented in `ExtractionService.LIMITS`. A worker has a ten-minute timeout. Archives are in memory through `adm-zip`; extracted searchable content is on disk. The string scan does not decompile source or perform control/data-flow analysis. JADX/apktool are intentionally not required or bundled: direct AXML decoding and compiled string inspection replace the original scaffold's proposed external-tool approach.

## Report contract

`AnalysisReport` contains identity/hash, per-package manifests/inventory and hashes, merged context, findings with evidence and recommendations, configuration assessment, optional separate AI assessment, malware assessment, per-APK reputation evidence, warnings and coverage. Malware and reputation fields are optional for backward compatibility; older reports display “Malware not assessed” and require a new scan. Reputation freshness is reevaluated when reports are opened. `ReportGenerator.buildHtmlReport` renders escaped HTML for both the viewer and PDF exporter. PDFs use `BrowserWindow.webContents.printToPDF`, with A4 pagination and page-number footers; there is no Puppeteer or system Chrome dependency.

Local score = 100 minus 25/high, 10/medium, 3/low category; info costs 0. Grades A/B/C/D/F use thresholds 90/75/60/40. Telemetry indicator score = 100 minus min(8 × SDK count, 48), minus 12 for any credential patterns. Scores are bounded to 0–100 and labeled heuristic. They never replace the evidence or claim verified safety.

## IPC

| Channel | Result |
| --- | --- |
| `select-file` | Absolute APK/XAPK path or undefined on cancellation |
| `analyze-apk` | Completed `AnalysisReport`; emits `analysis-progress` |
| `cancel-analysis` | Terminates the current worker or aborts a reputation request; an already accepted upload cannot be recalled |
| `get-settings` / `save-settings` | Validated `LLMSettings` |
| `list-reports` | Recent report summaries |
| `get-report` | Saved report by UUID |
| `get-report-html` | Escaped full report HTML by UUID |
| `export-pdf` | Saved path, or null if the save dialog is cancelled |
| `reputation-action` | Updated saved report after a hash lookup/status check or explicitly confirmed upload of one report APK |

Only the main renderer frame may invoke these handlers. Report IDs cannot be used as filesystem paths. The renderer never supplies arbitrary report HTML to PDF export.

## Persistence and privacy

`electron-store` stores non-secret settings. Separate AI and VirusTotal API keys use OS-backed `safeStorage`, or memory-only fallback when unavailable/basic-text; scaffold plaintext AI keys are migrated. AI requests run in the worker; VirusTotal requests run in main and its key is not passed to the worker. Provider errors are converted to generic warnings so credentials in request errors are not embedded in reports. Credential values are never retained by the scanner; URLs are reduced to origins. VirusTotal is disabled until explicitly enabled with an API key. Hash lookups disclose file interest; confirmed file submissions share the complete selected APK under VirusTotal's terms.

Completed reports are JSON in `userData/reports`, capped at 20; reports are not encrypted. PDF output goes only to the selected destination. Extraction uses the operating-system temp directory. Force-killing the entire application or the OS can leave temp files; normal completion, handled failure, cancel, window close and app quit have cleanup paths.

## Build

Vite builds the React renderer with relative asset URLs. `scripts/build-main.cjs` uses esbuild to bundle main, worker and preload as CommonJS; Electron is external. Main and worker runtime libraries are bundled; the build checks that remaining external imports are Electron or Node built-ins. `scripts/before-build.cjs` verifies the compiled entry points and tells electron-builder that runtime dependencies are already handled, avoiding duplicate `node_modules` packaging. Packaging uses the locally installed Electron distribution. `electron-builder.yml` configures platform targets. The production main entry is `dist/main/main.js`.

See [TEST_RESULTS.md](TEST_RESULTS.md) for automated and real-file validation. Unverified areas include actual cloud inference, runtime Android behavior, certificate verification, code signing and other OS builds.
