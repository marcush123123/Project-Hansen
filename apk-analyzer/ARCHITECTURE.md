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

1. Validate extension and file size; inspect ZIP paths, entry types/counts and expansion limits before writing selected files into a fresh temporary directory.
2. For XAPK, inspect every nested `.apk`. Require one base, consistent package/version code and unique split identifiers. Omitted split SDK and application flags inherit from the base. Container metadata cannot override decoded identity.
3. Decode Android binary XML string pools, typed attributes, element chunks and namespaces directly. Read ordinary text XML through `xml2js`; reject DTD/entity declarations. Decode permissions, SDK levels, flags and export semantics; manifest errors fail the scan instead of silently returning an empty clean result.
4. Inspect DEX, SO, resource tables and selected text files in 1 MiB chunks. Search Latin-1/UTF-16 strings for SDK namespaces, URL origins, credential patterns and code capability references. Record bounded file evidence and aggregate coverage.
5. Build structured `ContextJSON`; calculate deterministic local review findings and scores.
6. If enabled, send only that summary to the selected LLM. Validate its response fields and scores. Failure adds a warning while preserving local findings.
7. Return an `AnalysisReport`, persist it, keep the newest 20, and remove extraction files in `finally`. Main also removes temporary files after worker termination or error.

Resource bounds are implemented in `ExtractionService.LIMITS`. A worker has a ten-minute timeout. Archives are in memory through `adm-zip`; extracted searchable content is on disk. The string scan does not decompile source or perform control/data-flow analysis. JADX/apktool are intentionally not required or bundled: direct AXML decoding and compiled string inspection replace the original scaffold's proposed external-tool approach.

## Report contract

`AnalysisReport` contains identity/hash, per-package manifests/inventory, merged context, findings with evidence and recommendations, local assessment, optional separate AI assessment, warnings and coverage. `ReportGenerator.buildHtmlReport` is a pure HTML renderer used by both the app viewer and PDF exporter. PDFs use `BrowserWindow.webContents.printToPDF`, with A4 pagination and page-number footers; there is no Puppeteer or system Chrome dependency.

Local score = 100 minus 25/high, 10/medium, 3/low category; info costs 0. Grades A/B/C/D/F use thresholds 90/75/60/40. Telemetry indicator score = 100 minus min(8 × SDK count, 48), minus 12 for any credential patterns. Scores are bounded to 0–100 and labeled heuristic. They never replace the evidence or claim verified safety.

## IPC

| Channel | Result |
| --- | --- |
| `select-file` | Absolute APK/XAPK path or undefined on cancellation |
| `analyze-apk` | Completed `AnalysisReport`; emits `analysis-progress` |
| `cancel-analysis` | Terminates the current worker |
| `get-settings` / `save-settings` | Validated `LLMSettings` |
| `list-reports` | Recent report summaries |
| `get-report` | Saved report by UUID |
| `get-report-html` | Escaped full report HTML by UUID |
| `export-pdf` | Saved path, or null if the save dialog is cancelled |

Only the main renderer frame may invoke these handlers. Report IDs cannot be used as filesystem paths. The renderer never supplies arbitrary report HTML to PDF export.

## Persistence and privacy

`electron-store` stores non-secret settings. API keys use OS-backed `safeStorage`, or memory-only fallback when unavailable/basic-text; scaffold plaintext keys are migrated. API clients run in the worker. Provider errors are converted to generic report warnings so credentials in request errors are not embedded in reports. Credential values are never retained by the scanner; URLs are reduced to origins.

Completed reports are JSON in `userData/reports`, capped at 20; reports are not encrypted. PDF output goes only to the selected destination. Extraction uses the operating-system temp directory. Force-killing the entire application or the OS can leave temp files; normal completion, handled failure, cancel, window close and app quit have cleanup paths.

## Build

Vite builds the React renderer with relative asset URLs. `scripts/build-main.cjs` uses esbuild to bundle main, worker and preload as CommonJS; Electron is external. Main and worker runtime libraries are bundled; the build checks that remaining external imports are Electron or Node built-ins. `scripts/before-build.cjs` verifies the compiled entry points and tells electron-builder that runtime dependencies are already handled, avoiding duplicate `node_modules` packaging. Packaging uses the locally installed Electron distribution. `electron-builder.yml` configures platform targets. The production main entry is `dist/main/main.js`.

See [TEST_RESULTS.md](TEST_RESULTS.md) for automated and real-file validation. Unverified areas include actual cloud inference, runtime Android behavior, certificate verification, code signing and other OS builds.
