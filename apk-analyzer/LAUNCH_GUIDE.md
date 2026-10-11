# Launch and build guide

## Node.js setup

Building Hansen requires Node.js 22.12 or later and npm 10 or later. The repository's `.nvmrc` selects Node.js 24. The project enforces these requirements during dependency installation so an unsupported runtime fails before the Electron installer runs.

On Linux or macOS, install [nvm using its official instructions](https://github.com/nvm-sh/nvm#installing-and-updating), then open a new terminal. From `apk-analyzer`, run:

```bash
nvm install
nvm use
node --version
npm --version
npm ci --include=optional
npm run build
npm start
```

nvm reads `.nvmrc` from the repository root and installs Node together with npm. In each new terminal, run `nvm use` from the repository before using npm. On Windows, install Node.js 24 from [nodejs.org](https://nodejs.org/en/download), reopen the terminal, and verify both versions before building.

An install attempted with Node.js 12 can end with `ERR_REQUIRE_ESM` in Electron's installer. After selecting the supported runtime, rerun `npm ci --include=optional` to replace the incomplete dependency installation. Do not modify Electron's files or disable the engine check to work around the error.

## Built application

```bash
npm ci --include=optional
npm run build:vite
npm start
```

The compiled application loads `dist/renderer/index.html` from disk. A Vite server is unnecessary. The app's Electron runtime provides PDF rendering.

## Development

```bash
npm run dev
```

This first bundles main/worker/preload, then starts Vite on `127.0.0.1:5173` and Electron with `--dev`. The port is strict: an existing server causes an error instead of silently selecting another port. Renderer changes reload through Vite. Restart the command for main/worker/preload changes.

## Distribution

```bash
npm run build
```

Builds all entry points and runs electron-builder for the host OS. Output is in `build/`. Linux uses AppImage; Windows NSIS/portable and macOS DMG/ZIP are configured. Builds are unsigned unless signing is configured separately. Platform configurations are not proof that every platform was tested; consult [TEST_RESULTS.md](TEST_RESULTS.md).

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `EBADENGINE`, syntax errors, or Electron installer `ERR_REQUIRE_ESM` | Follow [Node.js setup](#nodejs-setup), verify Node and npm in this terminal, then rerun `npm ci --include=optional`. |
| Vite reports a missing native binding | Run `npm ci --include=optional` using current npm, then rebuild. |
| Empty window / missing bundle | Run `npm run build:vite` again and launch with `npm start`. Do not point plain Node at the Electron main file. |
| Port 5173 already in use | Stop the other server or use the compiled application. |
| Browser says no filesystem bridge | Launch Electron with `npm start`; opening Vite in a browser alone is only a UI preview. |
| `ENOSPC` during extraction | Free several GiB in the OS temp filesystem and retry. Handled failures remove that job's temp directory. |
| Corrupt/missing manifest or unsafe archive | Use a complete original APK/XAPK. Rejected packages do not produce a misleading clean report. |
| XAPK mismatch/incomplete base | Obtain a container with one base and matching package/version splits. |
| AI unavailable or invalid | Check model/key/provider connectivity, or select Local report only. Local analysis remains available. |
| API key disappears after restart | The OS secure-storage backend is unavailable; keys are session-only in that environment. |
| PDF export fails | Choose a writable destination with free disk space. The embedded report and history remain available for retry. |
| Linux Chromium sandbox failure | Run as a normal desktop user with the distribution's sandbox support configured. Do not disable sandboxing in distributed production builds. |

For automated UI tests on a display-less Linux machine, use `xvfb-run -a npm run test:electron`. The test-only environment variable `HANSEN_TEST_NO_SANDBOX=1` exists for constrained CI containers; it is not used by normal app launch or packaging.

## Cleanup

Quit the app before manually deleting local history. Report JSON lives in the app user-data `reports/` directory. Normally the app removes its `hansen-*` extraction directory when a job completes, fails or is cancelled. An OS crash/forced kill may leave stale temporary directories; only remove ones belonging to stopped Hansen jobs. Original packages and exported PDFs are never deleted by analysis cleanup.
