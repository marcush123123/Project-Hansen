# Getting started

1. Use Node.js 22.12 or later and npm 10 or later. Follow [Node.js setup](LAUNCH_GUIDE.md#nodejs-setup) to select the recommended Node.js 24, then confirm `node --version` and `npm --version` in the same terminal you will use to launch the app.
2. In `apk-analyzer`, run `npm ci --include=optional`, then `npm run build:vite`.
3. Run `npm start`. For renderer development, use `npm run dev` instead.
4. Drop one `.apk` or `.xapk` into the window, or use **Browse packages**.
5. Follow progress while the package is inspected. **Cancel analysis** stops the job and cleans temporary extraction data.
6. Read the full report in the embedded viewer. **Export PDF** saves a permanent copy; cancelling the save dialog leaves the report open.
7. Reopen recent completed reports in the sidebar, or choose **New analysis**.

No AI configuration is required. To add AI commentary, open **Analysis settings**, choose Ollama or a cloud provider, enter the model and required key, and save. A cloud selection sends structured metadata to that provider on subsequent scans. Raw code and credential values are not sent.

Large packages need free RAM and temporary disk space. The supplied TikTok APK is 472 MB compressed and expands to more than 1 GB. Keep several GiB free. See [README.md](README.md) for scan limits, privacy and reporting details, and [LAUNCH_GUIDE.md](LAUNCH_GUIDE.md) for troubleshooting.
